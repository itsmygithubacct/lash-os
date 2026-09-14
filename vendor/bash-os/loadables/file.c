/* SPDX-License-Identifier: MIT */
/* file.c — file(1)-style magic-byte file-type detection.
 *
 *   file [--help|--version] FILE [FILE...]
 *
 * Reads up to the first 512 bytes of each FILE and matches against a
 * curated table of magic-byte signatures. Output mirrors file(1):
 *   FILE: TYPE-DESCRIPTION
 *
 * Coverage: ELF (32/64, exec/dyn), MS-DOS executable, gzip, zlib, Unix compress,
 * xz, zstd, lzop, lrzip, Snappy framed, LZFSE, ZPAQ, bzip2, zip, jar,
 * 7z, tar (POSIX ustar), Debian package, Cabinet, WIM (Windows imaging), ZIM (offline-wiki container), CROMFS, Android bootimg, Android sparse image, U-Boot uImage, Chrome extension (CRX), XAR, Squashfs, cpio, cpio crc, ar archive, shell
 * script (#!/...), Python script, Perl script, JPEG, PNG, GIF, BMP,
 * TIFF, BigTIFF, PSD, PCX, XCF, JP2, JPEG XL, BPG, FLIF, Netpbm/PAM, WebP, Khronos KTX/KTX2 texture, PowerVR 3.0 texture, X11 PCF font, Sun rasterfile, DirectDraw Surface (DDS), Windows shortcut (.lnk), Windows registry hive, Zstandard dictionary, SQLite WAL, Git pack index, Group Policy registry policy, TZif timezone data, PEF executable, ALZip archive, KGB archive, VHDX disk image, NumPy array, MATLAB v5 mat-file, Vim swap file, AppleScript compiled, Java KeyStore (JKS/JCEKS), Redis RDB, ESRI Shapefile, OpenPGP public key, PDF, RIFF, AIFF/AIFF-C, AU, OGG/Opus/Vorbis, MP3, FLAC, WavPack, FLV, SWF (Shockwave Flash), MPEG, WebM, Matroska, MP4, AVIF, ISO9660,
 * SQLite3, Microsoft Access, GDBM (GNU dbm 2.x database), FITS, HDF5 (Hierarchical Data Format v5), Parquet, Avro, ORC, NetCDF, GRIB, WARC, BitTorrent, RealMedia, Doom IWAD/PWAD, Cineon, DPX, OpenPGP public/secret key, Git pack, ICO, icns, AppleSingle/AppleDouble, ICC, WOFF/WOFF2, TrueType, TrueType collection (ttcf), OpenType, age encrypted file, OpenSSH private key, CBOR data, DjVu document, Erlang BEAM, Python bytecode, Java class, Java serialization, Mach-O, Mach-O universal/fat binary,
 * LLVM bitcode, RPM, GNU message catalog, DICOM, OLE2 compound document, LUKS encrypted file, DOS/MBR boot sector, PEM certificate, PEM certificate request, PEM RSA private key, PEM EC private key, PEM DSA private key, PEM RSA public key, PGP armor (message/signature/public key block/private key block),
 * Dalvik DEX, Lua bytecode, Blender3D, QOI, MIDI, iNES ROM, Game Boy ROM, Apple binary plist, QEMU QCOW/VMware VMDK image, KeePass KDBX, OpenEXR, pcap/pcapng
 * including nanosecond-resolution pcap, WebAssembly, PostScript, HTML,
 * JSON (heuristic), XML, UTF-8/UTF-16/UTF-32 BOM text,
 * plus a generic "ASCII text" / "data" fallback.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>

#include "loadables.h"

#define BF_PROBE_LEN 512
#define BF_ISO9660_MAGIC_OFFSET 32769

typedef struct {
    int    offset;          /* byte offset to check */
    int    len;             /* number of magic bytes */
    const unsigned char *magic;
    const char *desc;
} bf_sig;

#define M(s) (const unsigned char *) (s)

/* Order matters — first match wins. Earlier entries should be more
   specific (e.g. ELF64 dyn before generic ELF). */
static const bf_sig bf_table[] = {
    /* ELF — magic 0x7F 'E' 'L' 'F'. We don't decode class/type here;
       the kernel reader can. */
    { 0, 4, M ("\x7f""ELF"), "ELF executable" },
    { 0, 2, M ("MZ"),                    "MS-DOS executable" },
    /* Compressed archives */
    { 0, 3, M ("\x1f\x8b\x08"),         "gzip compressed data" },
    { 0, 2, M ("\x1f\x9d"),             "compress'd data" },
    { 0, 6, M ("\xfd""7zXZ\x00"),       "XZ compressed data" },
    { 0, 4, M ("\x28\xb5\x2f\xfd"),     "Zstandard compressed data" },
    { 0, 4, M ("\x04\x22\x4d\x18"),     "LZ4 compressed data" },
    { 0, 4, M ("\x02\x21\x4c\x18"),     "LZ4 compressed data (legacy)" },
    { 0, 5, M ("LZIP\x01"),             "lzip compressed data" },
    { 0, 9, M ("\x89""LZO\x00\x0d\x0a\x1a\x0a"), "lzop compressed data" },
    { 0, 4, M ("LRZI"),                 "LRZIP compressed data" },
    { 0, 10, M ("\xff\x06\x00\x00""sNaPpY"), "Snappy framed data" },
    { 0, 3, M ("BZh"),                  "bzip2 compressed data" },
    /* LZFSE — Apple's Lempel-Ziv + Finite State Entropy codec (libcompression).
       4-byte block magic `bvx2` at offset 0 (sibling block types bvx-/bvxn use
       the same family; bvx2 is the dominant compressed-tables block). Host
       file(1) >= 5.40 returns "lzfse compressed, ..."; file emits the
       stem. */
    { 0, 4, M ("bvx2"),                 "lzfse compressed" },
    /* ZPAQ — the PAQ-family journaling/streaming archiver. 4-byte block
       magic `7kSt` at offset 0. Host file(1) >= 5.40 returns "ZPAQ file";
       file mirrors. */
    { 0, 4, M ("7kSt"),                 "ZPAQ file" },
    /* RNC / Rob Northen Compression ("Pro-Pack") archive. 4-byte magic
       `RNC\001` at offset 0. Host file(1) reports "PRO-PACK archive data
       (compression 1)" from this tag; file emits the stable stem. */
    { 0, 4, M ("RNC\x01"),              "PRO-PACK archive data" },
    { 0, 4, M ("PK\x03\x04"),           "Zip archive (or jar/odt/xlsx)" },
    { 0, 4, M ("PK\x05\x06"),           "Zip archive (empty)" },
    { 0, 6, M ("7z\xbc\xaf\x27\x1c"),   "7-zip archive" },
    { 0, 8, M ("Rar!\x1a\x07\x01\x00"), "RAR archive (v5)" },
    { 0, 7, M ("Rar!\x1a\x07\x00"),     "RAR archive (v1.5)" },
    { 0, 8, M ("MSCF\x00\x00\x00\x00"), "Microsoft Cabinet archive data" },
    /* WIM (Windows Imaging Format) — Microsoft filesystem-image archive used
       by the Windows installer (install.wim) and WinPE. 8-byte magic
       `MSWIM\x00\x00\x00` at offset 0. file(1) >= 5.40 emits "Windows imaging
       (WIM) image" plus a version suffix decoded from the header. */
    { 0, 8, M ("MSWIM\x00\x00\x00"),    "Windows imaging (WIM) image" },
    /* ZIM — openZIM offline-wiki container (Kiwix). 4-byte magic
       `ZIM\x04` at offset 0 (little-endian uint32 0x044D495A). Used by
       Wikipedia/Wiktionary/StackExchange snapshots distributed for
       offline reading. Host file(1) coverage of this magic depends on
       magdir vintage; file reports it unconditionally. */
    { 0, 4, M ("ZIM\x04"),              "ZIM archive" },
    { 0, 4, M ("Cr24"),                 "Google Chrome extension" },
    { 0, 4, M ("xar!"),                 "xar archive" },
    { 0, 4, M ("hsqs"),                 "Squashfs filesystem" },
    { 0, 4, M ("sqsh"),                 "Squashfs filesystem" },
    /* CROMFS — compressed read-only filesystem image. 6-byte ASCII tag
       `CROMFS` at offset 0 (followed by 2 version digits). Host file(1) >= 5.40
       returns "CROMFS"; file mirrors. */
    { 0, 6, M ("CROMFS"),               "CROMFS" },
    /* Android boot image (boot.img) — the AOSP kernel+ramdisk container. 8-byte
       magic `ANDROID!` at offset 0. Host file(1) >= 5.40 returns "Android
       bootimg"; file mirrors. */
    { 0, 8, M ("ANDROID!"),             "Android bootimg" },
    /* Android sparse image — the `simg` flashing format. 4-byte magic
       0xED26FF3A little-endian (`\x3a\xff\x26\xed`) at offset 0. Host file(1)
       >= 5.40 returns "Android sparse image, version: M.m, ..."; file
       emits the stem. */
    { 0, 4, M ("\x3a\xff\x26\xed"),     "Android sparse image" },
    /* Das U-Boot legacy uImage — the bootloader's wrapped kernel/ramdisk
       container. 4-byte big-endian magic 0x27051956 (`\x27\x05\x19\x56`) at
       offset 0. Host file(1) >= 5.40 returns "u-boot legacy uImage, ...";
       file emits the stem. */
    { 0, 4, M ("\x27\x05\x19\x56"),     "u-boot legacy uImage" },
    { 8, 13, M ("debian-binary"),        "Debian binary package (format 2.0)" },
    { 0, 8, M ("!<arch>\n"),            "ar archive (deb / .a)" },
    { 0, 6, M ("070701"),               "cpio archive (newc)" },
    { 0, 6, M ("070702"),               "cpio archive (crc)" },
    { 0, 6, M ("070707"),               "cpio archive (odc)" },
    { 0, 4, M ("\xed\xab\xee\xdb"),     "RPM package" },
    { 0, 4, M ("\xca\xfe\xba\xbe"),     "Java class data" },
    { 0, 4, M ("\xac\xed\x00\x05"),     "Java serialization data" },
    /* NumPy .npy array — the on-disk array format. 6-byte magic
       `\x93NUMPY` at offset 0 followed by a version byte pair. Host file(1)
       >= 5.40 returns "NumPy data file, version M.m"; file emits the
       stem. */
    { 0, 6, M ("\x93NUMPY"),            "NumPy data file" },
    /* MATLAB v5 MAT-file — the default .mat container (also MATLAB v7, which
       is a v5 file with a zlib-compressed payload). The first 19 bytes of the
       128-byte text header are the fixed banner `MATLAB 5.0 MAT-file`. Host
       file(1) >= 5.40 returns "Matlab v5 mat-file"; file emits the
       stem. */
    { 0, 19, M ("MATLAB 5.0 MAT-file"), "Matlab v5 mat-file" },
    /* Vim swap file (.swp) — the editor's crash-recovery journal. 6-byte
       magic `b0VIM ` (trailing space) at offset 0, followed by a version
       string. Host file(1) >= 5.40 returns "Vim swap file, version X.Y";
       file emits the stem. */
    { 0, 6, M ("b0VIM "),               "Vim swap file" },
    /* AppleScript compiled (.scpt) — the byte-compiled AppleScript container.
       7-byte magic `FasdUAS` at offset 0. Host file(1) >= 5.40 returns
       "AppleScript compiled"; file mirrors. */
    { 0, 7, M ("FasdUAS"),              "AppleScript compiled" },
    { 0, 8, M ("dex\n035\x00"),          "Dalvik dex file" },
    { 0, 8, M ("dex\n036\x00"),          "Dalvik dex file" },
    { 0, 8, M ("dex\n037\x00"),          "Dalvik dex file" },
    { 0, 8, M ("dex\n038\x00"),          "Dalvik dex file" },
    { 0, 8, M ("dex\n039\x00"),          "Dalvik dex file" },
    { 0, 8, M ("dex\n040\x00"),          "Dalvik dex file" },
    { 0, 4, M ("BC\xc0\xde"),           "LLVM IR bitcode" },
    { 0, 8, M ("bplist00"),              "Apple binary property list" },
    { 0, 4, M ("\x1b""Lua"),             "Lua bytecode" },
    { 0, 8, M ("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "OLE 2 Compound Document" },
    { 0, 4, M ("\xfe\xed\xfa\xce"),     "Mach-O executable (32-bit)" },
    { 0, 4, M ("\xce\xfa\xed\xfe"),     "Mach-O executable (32-bit)" },
    { 0, 4, M ("\xfe\xed\xfa\xcf"),     "Mach-O executable (64-bit)" },
    { 0, 4, M ("\xcf\xfa\xed\xfe"),     "Mach-O executable (64-bit)" },
    { 0, 4, M ("\xa1\xb2\xc3\xd4"),     "pcap capture file" },
    { 0, 4, M ("\xd4\xc3\xb2\xa1"),     "pcap capture file" },
    { 0, 4, M ("\xa1\xb2\x3c\x4d"),     "pcap capture file (nanosecond)" },
    { 0, 4, M ("\x4d\x3c\xb2\xa1"),     "pcap capture file (nanosecond)" },
    { 0, 4, M ("\x0a\x0d\x0d\x0a"),     "pcapng capture file" },
    { 0, 8, M ("\x00""asm\x01\x00\x00\x00"), "WebAssembly binary module" },
    { 0, 4, M ("\xde\x12\x04\x95"),     "GNU message catalog (little endian)" },
    { 0, 4, M ("\x95\x04\x12\xde"),     "GNU message catalog (big endian)" },
    { 0, 4, M ("\xf3\x0d\x0d\x0a"),     "Byte-compiled Python module" },
    { 0, 7, M ("BLENDER"),              "Blender3D data" },
    { 0, 4, M ("NES\x1a"),               "NES ROM image" },
    /* Game Boy / Game Boy Color cartridge — boot ROM verifies the 48-byte
       Nintendo logo at 0x104..0x133. The logo bytes are fixed; carts that
       fail this check will not boot on real hardware. */
    { 0x104, 48,
      M ("\xce\xed\x66\x66\xcc\x0d\x00\x0b\x03\x73\x00\x83\x00\x0c\x00\x0d"
         "\x00\x08\x11\x1f\x88\x89\x00\x0e\xdc\xcc\x6e\xe6\xdd\xdd\xd9\x99"
         "\xbb\xbb\x67\x63\x6e\x0e\xec\xcc\xdd\xdc\x99\x9f\xbb\xb9\x33\x3e"),
      "Game Boy ROM image" },
    { 0, 4, M ("QFI\xfb"),               "QEMU QCOW image" },
    { 0, 4, M ("KDMV"),                  "VMware4 disk image" },
    /* Microsoft VHDX — Hyper-V virtual hard disk v2. 8-byte container
       signature `vhdxfile` at offset 0. Host file(1) >= 5.40 returns
       "Microsoft Disk Image Extended, ..."; file emits the stem. */
    { 0, 8, M ("vhdxfile"),             "Microsoft Disk Image Extended" },
    { 0, 6, M ("LUKS\xba\xbe"),          "LUKS encrypted file" },
    /* KeePass KDBX — both v3 (sig2=0xB54BFB66) and v4 (sig2=0xB54BFB67)
       share the 4-byte primary signature 0x9AA2D903 LE. The 8-byte magic
       below covers v4 specifically (`Keepass password database, 2.x KDBX`
       per upstream file(1) >= 5.40). v3 carts would land a byte off but
       v4 is the dominant format since 2017. */
    { 0, 8, M ("\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"), "Keepass password database 2.x KDBX" },
    /* Java KeyStore — the JKS proprietary keystore. 4-byte magic 0xFEEDFEED
       (`\xfe\xed\xfe\xed`) at offset 0. Distinct from Mach-O 0xFEEDFACE/FACF
       and Java class 0xCAFEBABE. Host file(1) >= 5.40 returns "Java KeyStore";
       file mirrors. */
    { 0, 4, M ("\xfe\xed\xfe\xed"),     "Java KeyStore" },
    /* Java JCEKS keystore — the JCE variant. 4-byte magic 0xCECECECE
       (`\xce\xce\xce\xce`) at offset 0. Host file(1) >= 5.40 returns the more
       specific "Java JCE KeyStore"; file mirrors that exact phrase (not
       the bare "Java KeyStore" used for JKS above). */
    { 0, 4, M ("\xce\xce\xce\xce"),     "Java JCE KeyStore" },
    /* Redis RDB persistence file (dump.rdb) — 5-byte ASCII magic `REDIS` at
       offset 0, followed by a 4-digit version. Host file(1) >= 5.40 returns
       "Redis RDB file, version N"; file emits the stem. */
    { 0, 5, M ("REDIS"),                "Redis RDB file" },
    /* ESRI Shapefile (.shp / .shx) — GIS vector geometry container. 4-byte
       big-endian file-code magic 0x0000270A at offset 0. Host file(1) >= 5.40
       returns "ESRI Shapefile"; file mirrors. */
    { 0, 4, M ("\x00\x00\x27\x0a"),     "ESRI Shapefile" },
    /* OpenEXR — magic 0x01312F76 LE (`\x76\x2F\x31\x01`). file(1) appends
       version + storage decoded from the header; file labels the
       container alone. */
    { 0, 4, M ("\x76\x2f\x31\x01"),     "OpenEXR image data" },
    /* EDID — Extended Display Identification Data (monitor descriptor block).
       8-byte fixed header `\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00` at offset 0. Host
       file(1) >= 5.40 returns "EDID data, version M.m"; file emits the
       stem. The 8-byte all-or-nothing header is unambiguous. */
    { 0, 8, M ("\x00\xff\xff\xff\xff\xff\xff\x00"), "EDID data" },
    { 0, 4, M ("PAR1"),                  "Apache Parquet" },
    { 0, 4, M ("Obj\x01"),               "Apache Avro version 1" },
    { 0, 4, M ("ORC\x01"),               "Apache ORC" },
    /* NetCDF classic — Unidata network Common Data Form, classic (pre-HDF5)
       container. 4-byte magic `CDF\x01` (v1) / `CDF\x02` (64-bit offset) at
       offset 0. Host file(1) >= 5.40 returns "NetCDF Data Format data";
       file emits the "NetCDF data" stem. */
    { 0, 4, M ("CDF\x01"),               "NetCDF data" },
    { 0, 4, M ("CDF\x02"),               "NetCDF data" },
    /* GRIB — WMO GRIdded Binary, the standard meteorological gridded-data
       format. 4-byte ASCII magic `GRIB` at offset 0. Host file(1) >= 5.40
       returns "GRIB"; file mirrors. */
    { 0, 4, M ("GRIB"),                  "GRIB" },
    /* WARC — Web ARChive, the IIPC/IA web-crawl container. Text magic `WARC/`
       at offset 0 (followed by the version, e.g. `WARC/1.0`). Host file(1) >=
       5.40 returns "WARC Archive version M.m"; file emits the "WARC
       Archive" stem (host capitalizes "Archive"; the counterpart test matches
       case-insensitively). */
    { 0, 5, M ("WARC/"),                 "WARC Archive" },
    /* BitTorrent metainfo (.torrent) — bencoded dict that conventionally
       begins `d8:announce`. file(1)'s Magdir matches this exact 11-byte
       string; file mirrors it (a bare `d` bencode-dict opener is too
       generic — host returns "data" for it). Host returns "BitTorrent file". */
    { 0, 11, M ("d8:announce"),          "BitTorrent file" },
    /* RealMedia (.rm / .rmvb) — RealNetworks streaming container. 4-byte
       magic `.RMF` at offset 0. Host file(1) >= 5.40 returns "RealMedia
       file"; file mirrors. */
    { 0, 4, M (".RMF"),                  "RealMedia file" },
    { 4, 15, M ("Standard Jet DB"),       "Microsoft Access Database" },
    /* GDBM (GNU dbm) — the modern on-disk header (gdbm >= 1.13) opens with
       the 4-byte ASCII tag `GDBM` at offset 0, replacing the older numeric
       0x13579ace/0x13579acd magic words. Host file(1) >= 5.40 returns
       "GNU dbm 2.x database" verbatim from this tag alone (Magdir/database);
       file mirrors. The older numeric magics are deliberately NOT added:
       file(1) decodes endianness + bitness from surrounding header bytes
       (e.g. "GNU dbm 1.x or ndbm database, little endian, 32-bit"), which is
       not a single stable string, so no clean fixed-byte counterpart oracle
       exists for them. */
    { 0, 4, M ("GDBM"),                  "GNU dbm 2.x database" },
    /* Berkeley DB 1.85/1.86 hash database — historical libdb hash format.
       The fixed 4-byte magic 0x00053162 is the stable Magdir/database probe
       host file(1) labels as "Berkeley DB 1.85/1.86"; file mirrors that
       exact stem. Newer BDB formats encode richer metadata and are not added
       here without a clean fixed-byte counterpart oracle. */
    { 0, 4, M ("\x00\x05\x31\x62"),     "Berkeley DB 1.85/1.86" },
    /* FITS is NOT a flat-table entry — its "SIMPLE  =" prefix needs file(1)'s
       secondary offset-89 check (see bf_classify) to avoid false-positiving
       config/text files that merely begin with "SIMPLE  = ...". */
    /* HDF5 — Hierarchical Data Format v5. 8-byte magic
       `\x89HDF\r\n\x1a\n` at offset 0. The CR/LF/^Z/LF trailer is a
       deliberate "file-transfer corruption detector" (catches CRLF
       translation by FTP/text-mode tools). Dominant scientific data
       container for 20+ years (NetCDF-4, MATLAB v7.3, NumPy/h5py). */
    { 0, 8, M ("\x89HDF\r\n\x1a\n"),     "Hierarchical Data Format (version 5) data" },
    { 510, 2, M ("\x55\xaa"),            "DOS/MBR boot sector" },
    /* tar's ustar magic lives at offset 257 — handled outside this
       table after the first match miss. */

    /* Scripts (line 1 starts with #!) */
    { 0, 11, M ("#!/bin/bash"),         "Bash script" },
    { 0,  9, M ("#!/bin/sh"),           "POSIX shell script" },
    { 0, 18, M ("#!/usr/bin/env bash"), "Bash script (env shebang)" },
    { 0, 16, M ("#!/usr/bin/env sh"),   "POSIX shell script (env shebang)" },
    { 0, 19, M ("#!/usr/bin/env python"), "Python script (env shebang)" },
    { 0, 14, M ("#!/usr/bin/python"),   "Python script" },
    { 0, 17, M ("#!/usr/bin/env perl"), "Perl script" },
    { 0, 12, M ("#!/usr/bin/perl"),     "Perl script" },
    { 0,  2, M ("#!"),                  "script (with shebang)" },

    /* Images */
    { 0, 4, M ("\x89""PNG"),            "PNG image" },
    { 0, 3, M ("\xff\xd8\xff"),         "JPEG image" },
    { 0, 6, M ("GIF87a"),               "GIF image (87a)" },
    { 0, 6, M ("GIF89a"),               "GIF image (89a)" },
    { 0, 2, M ("BM"),                   "BMP image" },
    { 0, 4, M ("8BPS"),                 "Adobe Photoshop image" },
    { 0, 4, M ("II+\x00"),              "BigTIFF image (little-endian)" },
    { 0, 4, M ("MM\x00+"),              "BigTIFF image (big-endian)" },
    { 0, 4, M ("II*\x00"),              "TIFF image (little-endian)" },
    { 0, 4, M ("MM\x00*"),              "TIFF image (big-endian)" },
    { 0, 4, M ("\x0a\x05\x01\x08"),     "PCX image data" },
    { 0, 8, M ("gimp xcf"),             "GIMP XCF image data" },
    { 4, 8, M ("jP  \x0d\x0a\x87\x0a"), "JPEG 2000 Part 1 (JP2)" },
    { 4, 8, M ("JXL \x0d\x0a\x87\x0a"), "JPEG XL container" },
    { 0, 2, M ("\xff\x0a"),             "JPEG XL codestream" },
    { 0, 4, M ("BPG\xfb"),              "BPG (Better Portable Graphics)" },
    { 0, 4, M ("FLIF"),                 "FLIF image data" },
    { 36, 4, M ("acsp"),                "ICC color profile" },
    { 0, 4, M ("RIFF"),                 "RIFF container (WebP / WAV / AVI)" },
    { 0, 4, M ("\x00\x00\x01\x00"),     "Windows ICO" },
    { 0, 4, M ("icns"),                 "Mac OS X icon" },
    /* AppleSingle / AppleDouble — classic Mac OS resource-fork containers.
       Magic differs only in the trailing byte (\x00 = AppleSingle,
       \x07 = AppleDouble). file(1) labels per the Magdir/apple entries. */
    { 0, 4, M ("\x00\x05\x16\x00"),     "AppleSingle encoded Macintosh file" },
    { 0, 4, M ("\x00\x05\x16\x07"),     "AppleDouble encoded Macintosh file" },

    /* Audio / video */
    { 0, 4, M (".snd"),                 "Sun/NeXT audio data" },
    { 0, 3, M ("FLV"),                  "Macromedia Flash Video" },
    /* SWF (Shockwave Flash) — 3-byte codec prefix + 1-byte version + 4-byte
       LE length + codec-specific header byte at offset 8. file(1) splits by
       prefix: FWS = uncompressed, CWS = zlib (0x78 at offset 8),
       ZWS = LZMA (0x5d at offset 8). Three table entries are simpler than a
       single-byte dispatch and stay within the existing magic-byte idiom;
       the trailing version/length predicates only matter for upstream
       file(1)'s stricter validity check — file labels by codec family. */
    { 0, 3, M ("FWS"),                  "Macromedia Flash data" },
    { 0, 3, M ("CWS"),                  "Macromedia Flash data (compressed)" },
    { 0, 3, M ("ZWS"),                  "Macromedia Flash data (lzma compressed)" },
    { 0, 4, M ("\x00\x00\x01\xba"),     "MPEG sequence" },
    { 0, 4, M ("OggS"),                 "Ogg container" },
    { 0, 4, M ("fLaC"),                 "FLAC audio" },
    /* WavPack — open-source lossless/lossy audio codec. 4-byte ASCII
       magic `wvpk` at offset 0, followed by a 32-byte block header
       (block_size, version, track/index numbers, sample count, flags,
       CRC). Magic stable since the WavPack 4.x format (~2004); ships
       in upstream Magdir/audio. */
    { 0, 4, M ("wvpk"),                 "WavPack encoded audio" },
    { 0, 3, M ("ID3"),                  "MP3 audio (with ID3)" },
    { 0, 4, M ("MThd"),                 "Standard MIDI data" },
    { 0, 4, M ("qoif"),                 "QOI image data" },
    /* Khronos KTX texture — GPU texture container (OpenGL/Vulkan). 12-byte
       identifier `\xABKTX 11\xBB\r\n\x1A\n` at offset 0 (the embedded "11"
       is the v1.1 version and the trailing CR/LF/^Z/LF is an IFF-style
       newline guard). Host file(1) >= 5.40 returns "Khronos KTX texture
       (version 1.1)"; file emits the terse stem. The 12-byte magic is
       maximally specific — no ambiguity risk. */
    { 0, 12, M ("\xab""KTX 11\xbb\x0d\x0a\x1a\x0a"), "Khronos KTX texture" },
    /* Khronos KTX2 texture — the Basis-Universal-era successor container. Same
       12-byte identifier shape as KTX1 but with the embedded version "20"
       (`\xABKTX 20\xBB\r\n\x1A\n`). Host file(1) >= 5.40 returns "Khronos KTX2
       texture"; file mirrors. Must precede no other 12-byte ^\xAB entry
       (distinct from the KTX1 "11" magic above). */
    { 0, 12, M ("\xab""KTX 20\xbb\x0d\x0a\x1a\x0a"), "Khronos KTX2 texture" },
    /* PowerVR 3.0 texture — Imagination Technologies GPU texture container
       (PVR v3 header). 4-byte magic `PVR\x03` at offset 0. Host file(1) >= 5.40
       returns "PowerVR 3.0 texture: W x H, ..."; file emits the terse
       stem. */
    { 0, 4, M ("PVR\x03"),              "PowerVR 3.0 texture" },
    /* Sun rasterfile — classic SunOS raster image. 4-byte big-endian magic
       0x59A66A95 at offset 0 (the "rasterfile magic" RAS_MAGIC). Host file(1)
       >= 5.40 returns "Sun raster image data" plus decoded dimensions;
       file emits the terse stem. The 4-byte magic is unambiguous. */
    { 0, 4, M ("\x59\xa6\x6a\x95"),     "Sun raster image data" },
    /* Microsoft DirectDraw Surface (DDS) — GPU texture container. 4-byte
       magic `DDS ` (0x44 0x44 0x53 0x20) at offset 0. Host file(1) >= 5.40
       returns "Microsoft DirectDraw Surface (DDS): W x H"; file emits the
       terse stem. */
    { 0, 4, M ("DDS "),                 "Microsoft DirectDraw Surface" },
    /* Microsoft Windows shortcut (.lnk) — Shell Link Binary File Format. The
       first 20 bytes are the fixed header size 0x0000004C followed by the
       Shell Link CLSID {00021401-0000-0000-C000-000000000046}. Matching all
       20 bytes is maximally specific. Host file(1) >= 5.40 returns
       "MS Windows shortcut"; file mirrors the stem. */
    { 0, 20, M ("\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"),
      "MS Windows shortcut" },
    /* Microsoft Windows registry hive — `regf` 4-byte magic at offset 0
       (NT/2000-and-later registry file). Host file(1) >= 5.40 returns
       "MS Windows registry file, NT/2000 or above"; file emits the stem. */
    { 0, 4, M ("regf"),                 "MS Windows registry file" },
    /* Zstandard dictionary — 4-byte magic 0xEC30A437 (`\x37\xa4\x30\xec`,
       little-endian) at offset 0. Distinct from the zstd *compressed* frame
       magic 0xFD2FB528 above. Host file(1) >= 5.40 returns "Zstandard
       dictionary (ID N)"; file emits the stem. */
    { 0, 4, M ("\x37\xa4\x30\xec"),     "Zstandard dictionary" },
    /* Microsoft Group Policy registry policy (.pol / Registry.pol) — `PReg`
       4-byte magic at offset 0 (followed by a little-endian version dword).
       Host file(1) >= 5.40 returns "Group Policy Registry Policy, Version=N";
       file emits the stem. */
    { 0, 4, M ("PReg"),                 "Group Policy Registry Policy" },
    /* tzfile / TZif — IANA compiled timezone data. 4-byte magic `TZif` at
       offset 0 (RFC 8536). Host file(1) >= 5.40 returns "timezone data ...";
       file emits the stem. */
    { 0, 4, M ("TZif"),                 "timezone data" },
    /* PEF — classic Mac OS / PowerPC Preferred Executable Format. 8-byte
       container tag `Joy!peff` at offset 0. Host file(1) >= 5.40 returns
       "header for PowerPC PEF executable"; file emits the "PEF
       executable" stem (a substring of the host phrase). */
    { 0, 8, M ("Joy!peff"),             "PEF executable" },
    /* ALZip archive — Korean archiver format. 4-byte magic `ALZ\x01` at
       offset 0. Host file(1) >= 5.40 returns "ALZ archive data"; file
       mirrors. */
    { 0, 4, M ("ALZ\x01"),              "ALZ archive data" },
    /* KGB archive — PAQ-family high-ratio archiver. 8-byte magic `KGB_arch`
       at offset 0. Host file(1) >= 5.40 returns "KGB Archiver file ...";
       file emits the "KGB Archiver file" stem. */
    { 0, 8, M ("KGB_arch"),             "KGB Archiver file" },
    { 0, 4, M ("wOFF"),                 "Web Open Font Format" },
    { 0, 4, M ("wOF2"),                 "Web Open Font Format (Version 2)" },
    { 0, 4, M ("\x00\x01\x00\x00"),     "TrueType font data" },
    { 0, 4, M ("OTTO"),                 "OpenType font data" },
    { 0, 4, M ("ttcf"),                 "TrueType font collection data" },
    /* X11 Portable Compiled Font (PCF) — the compiled bitmap-font format used
       by the classic X server. 4-byte magic `\x01fcp` at offset 0 (the ASCII
       "fcp" reversed, with a leading 0x01). Host file(1) >= 5.40 returns "X11
       Portable Compiled Font data, ..."; file emits the terse stem. */
    { 0, 4, M ("\x01""fcp"),            "X11 Portable Compiled Font" },
    { 4, 8, M ("ftypisom"),             "MP4 (ISO base media)" },
    { 4, 8, M ("ftypMSNV"),             "MP4 (movie)" },
    { 4, 8, M ("ftypavif"),             "AVIF image" },
    /* HEIF/HEIC ftyp brands — file(1) distinguishes the HEVC profile per
       major-brand at offset 8. heic = Main/Main-Still, heix = Main-10,
       mif1 = generic Image File. Within the existing 512-byte probe. */
    { 4, 8, M ("ftypheic"),             "HEIC image (HEVC Main profile)" },
    { 4, 8, M ("ftypheix"),             "HEIC image (HEVC Main 10 profile)" },
    { 4, 8, M ("ftypmif1"),             "HEIF image" },

    /* Documents */
    { 0, 5, M ("%PDF-"),                "PDF document" },
    { 0, 4, M ("%!PS"),                 "PostScript document" },
    { 0, 5, M ("{\\rtf"),               "Rich Text Format data" },
    { 0, 22, M ("age-encryption.org/v1\n"), "age encrypted file" },
    { 0, 36, M ("-----BEGIN OPENSSH PRIVATE "
                  "KEY-----\n"), "OpenSSH private key" },
    /* PEM certificate — RFC 7468 textual encoding of X.509 certificates.
       27-byte text prefix `-----BEGIN CERTIFICATE-----`. Ubiquitous TLS
       trust-anchor / leaf-cert artifact (ca-certificates bundles, ACME
       issuance output, openssl x509 -outform pem). Host file(1) >= 5.40
       returns "PEM certificate" verbatim; file mirrors. The match
       intentionally fires before the OpenSSH entry above stays separate
       (different BEGIN body, no ambiguity). */
    { 0, 27, M ("-----BEGIN CERTIFICATE-----"), "PEM certificate" },
    /* PEM RSA PRIVATE KEY — RFC 7468 textual encoding of a PKCS#1 RSA
 * Private-key armour prefixes are recognized by the magic table below.
       Common artifact from `openssl genrsa -out key.pem`, legacy
       Apache/nginx keys, and any tool that emits PKCS#1 rather than the
 * Private-key armour prefixes are recognized by the magic table below.
       >= 5.40 returns "PEM RSA private key" verbatim from Magdir/pgp;
       file mirrors. Distinct from the 36-byte OpenSSH PRIVATE KEY
       entry above (different BEGIN body, no ambiguity). */
    { 0, 31, M ("-----BEGIN RSA PRIVATE "
                  "KEY-----"), "PEM RSA private key" },
    /* PEM EC PRIVATE KEY — RFC 7468 textual encoding of an SEC1 elliptic-curve
 * Private-key armour prefixes are recognized by the magic table below.
       Emitted by `openssl ecparam -genkey` / `openssl ec` and any tool that
       writes the SEC1 envelope rather than the newer PKCS#8 generic
 * Private-key armour prefixes are recognized by the magic table below.
       "PEM EC private key" verbatim from Magdir/pgp; file mirrors.
       Distinct from the RSA / CERTIFICATE / OPENSSH / age entries above
       (different BEGIN body, no ambiguity). The PKCS#8 generic
 * Private-key armour prefixes are recognized by the magic table below.
       host file(1) 5.46 misclassifies it as "OpenSSH private key (no
       password)", so no clean counterpart oracle exists for it. */
    { 0, 30, M ("-----BEGIN EC PRIVATE "
                  "KEY-----"), "PEM EC private key" },
    /* PEM DSA PRIVATE KEY — RFC 7468 textual encoding of a DSA private key.
 * Private-key armour prefixes are recognized by the magic table below.
       `openssl dsaparam`/`openssl gendsa` and legacy DSA keypairs. Host
       file(1) >= 5.40 returns "PEM DSA private key" verbatim from Magdir/pgp;
       file mirrors. Distinct from the RSA / EC / CERTIFICATE / OPENSSH /
       age entries above (different BEGIN body, no ambiguity). */
    { 0, 31, M ("-----BEGIN DSA PRIVATE "
                  "KEY-----"), "PEM DSA private key" },
    /* PEM RSA PUBLIC KEY — RFC 7468 textual encoding of a PKCS#1 RSA public
       key. 30-byte text prefix `-----BEGIN RSA PUBLIC KEY-----`. Emitted by
       `openssl rsa -RSAPublicKey_out` and tooling that writes the PKCS#1
       (RSAPublicKey) form rather than the generic SPKI
       `-----BEGIN PUBLIC KEY-----` envelope. Host file(1) >= 5.40 returns
       "PEM RSA public key" verbatim from Magdir/pgp; file mirrors.
       Distinct from the RSA/EC/DSA private-key and CERTIFICATE/OPENSSH/age
       entries above (different BEGIN body, no ambiguity). The generic SPKI
       `-----BEGIN PUBLIC KEY-----` envelope is deliberately NOT added: host
       file(1) 5.46 misclassifies it as "OpenSSH public key", so no clean
       counterpart oracle exists for it (same situation as PKCS#8 private). */
    { 0, 30, M ("-----BEGIN RSA PUBLIC KEY-----"), "PEM RSA public key" },
    /* PEM CERTIFICATE REQUEST (PKCS#10 CSR) — RFC 7468 textual encoding of a
       certification request. 35-byte text prefix
       `-----BEGIN CERTIFICATE REQUEST-----`. Emitted by `openssl req -new`
       and ACME / CA enrollment tooling. Host file(1) >= 5.40 returns
       "PEM certificate request" verbatim from Magdir/pgp; file mirrors.
       Distinct from the CERTIFICATE / key entries above (different BEGIN
       body, no ambiguity). The older `-----BEGIN NEW CERTIFICATE REQUEST-----`
       (Netscape/IIS) spelling is deliberately NOT added: host file(1) 5.46
       returns "data" for it (magdir lacks the entry), so no clean counterpart
 * Private-key armour prefixes are recognized by the magic table below.
       added — host file(1) 5.46 misclassifies it as "OpenSSH private key
       (with password)". */
    { 0, 35, M ("-----BEGIN CERTIFICATE REQUEST-----"), "PEM certificate request" },
    /* PGP ASCII-armor cluster — RFC 4880 §6.2 textual armor headers. Each is
       an `-----BEGIN PGP <kind>-----` text prefix at offset 0. Emitted by
       GnuPG (`gpg --armor`) and any OpenPGP tooling. Host file(1) >= 5.40
       classifies each from the BEGIN line alone (Magdir/gnu) and returns the
       lowercase phrases below verbatim; file mirrors. Lengths are exact
       full-prefix matches. Distinct from the PEM `-----BEGIN` entries above
       (the 8th byte `P` of "PGP" diverges from PEM bodies, no ambiguity). */
    { 0, 27, M ("-----BEGIN PGP MESSAGE-----"),           "PGP message" },
    { 0, 29, M ("-----BEGIN PGP SIGNATURE-----"),         "PGP signature" },
    { 0, 36, M ("-----BEGIN PGP PUBLIC KEY BLOCK-----"),  "PGP public key block" },
    { 0, 37, M ("-----BEGIN PGP PRIVATE "
                  "KEY BLOCK-----"), "PGP private key block" },
    /* OpenPGP binary public-key packet — RFC 4880 old-format packet header for
       a Public-Key packet (tag 6): byte 0 = 0x99 (0x80 | tag<<2 | len-type),
       byte 1 high of the 2-octet length. file(1)'s Magdir/gnupg matches the
       2-byte beshort 0x9901 here; file mirrors that exact (admittedly
       loose) 2-byte magic to preserve counterpart parity. Placed after the
       ASCII-armor cluster; 0x99 is a high byte so it cannot shadow any text
       or the other binary magics above. */
    { 0, 2, M ("\x99\x01"),             "OpenPGP Public Key" },
    /* OpenPGP binary secret-key packet — RFC 4880 old-format packet header for
       a Secret-Key packet (tag 5): byte 0 = 0x95, byte 1 high of the 2-octet
       length. Mirrors file(1)'s Magdir/gnupg beshort 0x9501; file uses the
       same 2-byte magic for counterpart parity. Host returns "OpenPGP Secret
       Key". 0x95 is a high byte so it cannot shadow text or other magics. */
    { 0, 2, M ("\x95\x01"),             "OpenPGP Secret Key" },
    /* Doom IWAD — the main game-data archive (id Software WAD format). 4-byte
       magic `IWAD` at offset 0. Host file(1) >= 5.40 returns "doom main IWAD
       data ..."; file emits the "IWAD" stem. */
    { 0, 4, M ("IWAD"),                 "Doom IWAD" },
    /* Doom PWAD — a patch/add-on WAD (mods, custom levels). 4-byte magic
       `PWAD` at offset 0. Host file(1) >= 5.40 returns "doom patch PWAD data
       ..."; file emits the "PWAD" stem. */
    { 0, 4, M ("PWAD"),                 "Doom PWAD" },
    /* Cineon image — Kodak digital-film scan format. 4-byte big-endian magic
       0x802A5FD7 (`\x80\x2a\x5f\xd7`) at offset 0. Host file(1) >= 5.40
       returns "Cineon image data"; file mirrors. */
    { 0, 4, M ("\x80\x2a\x5f\xd7"),     "Cineon image data" },
    /* SMPTE DPX image — Digital Picture eXchange (film/VFX frame). 4-byte
       magic `SDPX` (big-endian) or `XPDS` (little-endian) at offset 0. Host
       file(1) >= 5.40 returns "DPX image data, ..."; file emits the
       "DPX image data" stem. */
    { 0, 4, M ("SDPX"),                 "DPX image data" },
    { 0, 4, M ("XPDS"),                 "DPX image data" },
    { 0, 3, M ("\xd9\xd9\xf7"),          "CBOR data" },
    { 0, 11, M ("BEGIN:VCARD"),         "vCard visiting card" },
    { 0, 15, M ("BEGIN:VCALENDAR"),     "iCalendar calendar file" },
    { 0, 3, M ("\xef\xbb\xbf"),         "Unicode text, UTF-8 (with BOM) text" },
    { 0, 4, M ("\xff\xfe\x00\x00"),     "Unicode text, UTF-32, little-endian" },
    { 0, 4, M ("\x00\x00\xfe\xff"),     "Unicode text, UTF-32, big-endian" },
    { 0, 2, M ("\xff\xfe"),             "Unicode text, UTF-16, little-endian text" },
    { 0, 2, M ("\xfe\xff"),             "Unicode text, UTF-16, big-endian text" },
    { 0, 16, M ("SQLite format 3\x00"), "SQLite 3 database" },
    /* SQLite Write-Ahead Log — the `-wal` sidecar of a SQLite database in WAL
       journal mode. 4-byte big-endian magic 0x377F0682 (or 0x377F0683 for the
       checksum variant; both share the first three bytes). Host file(1) >= 5.40
       returns "SQLite Write-Ahead Log, version N"; file emits the stem. */
    { 0, 4, M ("\x37\x7f\x06\x82"),     "SQLite Write-Ahead Log" },
    { 0, 4, M ("\x37\x7f\x06\x83"),     "SQLite Write-Ahead Log" },
    /* Git pack index (.idx) — the companion index to a Git packfile. 8-byte
       magic `\xfftOc` + 4-byte big-endian version (0x00000002). Distinct from
       the packfile itself (`PACK`, special-cased in bf_classify). Host file(1)
       >= 5.40 returns "Git pack index, version 2"; file emits the stem. */
    { 0, 8, M ("\xfftOc\x00\x00\x00\x02"), "Git pack index" },
    { 0, 5, M ("<?xml"),                "XML document" },
    { 128, 4, M ("DICM"),               "DICOM medical imaging data" },
};

#define BF_NSIGS (sizeof bf_table / sizeof bf_table[0])

static int
bf_is_text (const unsigned char *p, size_t n)
{
    /* "ASCII text" if every byte is printable ASCII or one of the
       common controls (\n \t \r \b \f). Stop early on any other. */
    for (size_t i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '\n' || c == '\t' || c == '\r' || c == '\b' || c == '\f') continue;
        if (c < 0x20 || c == 0x7f) return 0;
    }
    return 1;
}

/* Returns 0 = pure ASCII (no high bytes), 1 = valid UTF-8 with non-ASCII,
   -1 = high bytes that don't form valid UTF-8 sequences. The tristate lets
   the caller emit "ASCII text" vs "UTF-8 text" distinctly (file(1) parity)
   while still treating ill-formed high-byte streams as ISO-8859-ish text
   rather than collapsing to "data". */
static int
bf_utf8_classify (const unsigned char *p, size_t n)
{
    size_t i = 0;
    int has_high = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c < 0x80) { i++; continue; }
        has_high = 1;
        int needed = 0;
        if      ((c & 0xe0) == 0xc0) needed = 1;
        else if ((c & 0xf0) == 0xe0) needed = 2;
        else if ((c & 0xf8) == 0xf0) needed = 3;
        else return -1;
        if (i + needed >= n) return -1;
        for (int k = 1; k <= needed; k++)
            if ((p[i + k] & 0xc0) != 0x80) return -1;
        i += needed + 1;
    }
    return has_high ? 1 : 0;
}

static int
bf_syncsafe32 (const unsigned char *p, size_t *out)
{
    if ((p[0] | p[1] | p[2] | p[3]) & 0x80)
        return 0;
    *out = ((size_t) p[0] << 21) |
           ((size_t) p[1] << 14) |
           ((size_t) p[2] << 7) |
           (size_t) p[3];
    return 1;
}

static unsigned long
bf_be32 (const unsigned char *p)
{
    return ((unsigned long) p[0] << 24) |
           ((unsigned long) p[1] << 16) |
           ((unsigned long) p[2] << 8) |
           (unsigned long) p[3];
}

static unsigned int
bf_le16 (const unsigned char *p)
{
    return (unsigned int) p[0] | ((unsigned int) p[1] << 8);
}

static unsigned int
bf_be16 (const unsigned char *p)
{
    return ((unsigned int) p[0] << 8) | (unsigned int) p[1];
}

static const char *
bf_elf_desc (const unsigned char *p, size_t n)
{
    if (n < 18 || memcmp (p, "\x7f""ELF", 4) != 0)
        return NULL;

    unsigned int type;
    if (p[5] == 1)       /* ELFDATA2LSB */
        type = bf_le16 (p + 16);
    else if (p[5] == 2)  /* ELFDATA2MSB */
        type = bf_be16 (p + 16);
    else
        return "ELF executable";

    switch (type) {
    case 1: return "ELF relocatable";
    case 2: return "ELF executable";
    case 3: return "ELF shared object";
    case 4: return "ELF core file";
    default: return "ELF executable";
    }
}

static int
bf_contains (const unsigned char *p, size_t n, const char *needle)
{
    size_t len = strlen (needle);

    if (len == 0 || len > n)
        return 0;
    for (size_t i = 0; i + len <= n; i++)
        if (memcmp (p + i, needle, len) == 0)
            return 1;
    return 0;
}

static const unsigned char *
bf_skip_ws (const unsigned char *p, size_t n, size_t *remain)
{
    size_t i = 0;

    while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r' || p[i] == '\n'))
        i++;
    *remain = n - i;
    return p + i;
}

static int
bf_starts_ci (const unsigned char *p, size_t n, const char *prefix)
{
    size_t len = strlen (prefix);

    if (len > n)
        return 0;
    for (size_t i = 0; i < len; i++)
        if ((unsigned char) tolower (p[i]) != (unsigned char) prefix[i])
            return 0;
    return 1;
}

static const char *
bf_netpbm_desc (const unsigned char *p, size_t n)
{
    if (n < 3 || p[0] != 'P' ||
        !(p[2] == ' ' || p[2] == '\t' || p[2] == '\r' || p[2] == '\n'))
        return NULL;

    if (p[1] >= '2' && p[1] <= '6')
        return "Netpbm image data";
    if (p[1] == '7')
        return "Netpbm PAM image file";
    return NULL;
}

static const char *
bf_zlib_desc (const unsigned char *p, size_t n)
{
    if (n < 2)
        return NULL;

    unsigned int cmf = p[0];
    unsigned int flg = p[1];

    if ((cmf & 0x0f) == 8 &&          /* deflate compression method */
        (cmf >> 4) <= 7 &&            /* window size allowed by RFC 1950 */
        ((cmf << 8) + flg) % 31 == 0)
        return "zlib compressed data";
    return NULL;
}

static const char *
bf_git_pack_desc (const unsigned char *p, size_t n)
{
    if (n < 12 || memcmp (p, "PACK", 4) != 0)
        return NULL;

    unsigned long version = bf_be32 (p + 4);
    if (version == 2 || version == 3)
        return "Git pack";
    return NULL;
}

static const char *
bf_classify (const unsigned char *probe, size_t n)
{
    static char tar_buf[64];
    const char *elf = bf_elf_desc (probe, n);
    if (elf)
        return elf;

    /* tar ustar magic at offset 257 (within probe). */
    if ((n >= 263 && memcmp (probe + 257, "ustar\0", 6) == 0) ||
        (n >= 264 && memcmp (probe + 257, "ustar  ", 7) == 0)) {
        snprintf (tar_buf, sizeof tar_buf, "POSIX tar archive");
        return tar_buf;
    }

    /* RIFF subtypes — "RIFF" + 4-byte little-endian length + 4-byte
       form-type tag at offset 8. Checked before the generic RIFF
       table entry so WebP/WAVE/AVI get specific labels. */
    if (n >= 12 && memcmp (probe, "RIFF", 4) == 0) {
        if (memcmp (probe + 8, "WEBP", 4) == 0) {
            /* WebP chunk at offset 12 selects the codec subtype:
               "VP8 " (trailing space) = lossy, "VP8L" = lossless,
               "VP8X" = extended (alpha/animation). Mirrors file(1) which
               appends ", lossless" / ", with alpha" past the base label. */
            if (n >= 16 && memcmp (probe + 12, "VP8L", 4) == 0)
                return "WebP image (lossless)";
            if (n >= 16 && memcmp (probe + 12, "VP8X", 4) == 0)
                return "WebP image (extended)";
            return "WebP image";
        }
        if (memcmp (probe + 8, "WAVE", 4) == 0) return "WAVE audio";
        if (memcmp (probe + 8, "AVI ", 4) == 0) return "AVI video";
    }

    /* IFF FORM containers use a big-endian length and a form-type tag
       at offset 8. Keep the scoped audio subtype separate from RIFF. */
    if (n >= 12 && memcmp (probe, "FORM", 4) == 0) {
        if (memcmp (probe + 8, "AIFF", 4) == 0) return "AIFF audio";
        if (memcmp (probe + 8, "AIFC", 4) == 0) return "AIFF-C audio";
    }

    /* Erlang BEAM — IFF-like container used by the Erlang VM. The file begins
       with a FOR1/FOR2/FOR3/FOR4 tag, a 32-bit size, then the BEAM form tag at
       offset 8. This is deliberately a two-span check; matching bare FOR1
       would be weaker than host file(1)'s Magdir rule and would collide with
       generic IFF-family data. */
    if (n >= 12 &&
        (memcmp (probe, "FOR1", 4) == 0 || memcmp (probe, "FOR2", 4) == 0 ||
         memcmp (probe, "FOR3", 4) == 0 || memcmp (probe, "FOR4", 4) == 0) &&
        memcmp (probe + 8, "BEAM", 4) == 0)
        return "Erlang BEAM file";

    /* DjVu — AT&T-prefixed IFF variant. "AT&T" + "FORM" + 4-byte BE
       length + 4-byte brand at offset 12 (DJVU single page, DJVM multi
       page, DJVI shared component, THUM thumbnails). Mirrors file(1)
       which splits single-page vs multiple-page output. */
    if (n >= 16 && memcmp (probe, "AT&TFORM", 8) == 0) {
        if (memcmp (probe + 12, "DJVM", 4) == 0) return "DjVu multiple page document";
        if (memcmp (probe + 12, "DJVU", 4) == 0) return "DjVu image or single page document";
        if (memcmp (probe + 12, "DJVI", 4) == 0) return "DjVu shared document";
        if (memcmp (probe + 12, "THUM", 4) == 0) return "DjVu thumbnail document";
        return "DjVu document";
    }

    const char *netpbm = bf_netpbm_desc (probe, n);
    if (netpbm)
        return netpbm;

    const char *zlib = bf_zlib_desc (probe, n);
    if (zlib)
        return zlib;

    const char *git_pack = bf_git_pack_desc (probe, n);
    if (git_pack)
        return git_pack;

    /* ID3v2 can be a metadata prefix before another audio bitstream.
       Parse the syncsafe tag size so small tagged FLAC fixtures are not
       mislabeled as MP3 solely because the file starts with "ID3". */
    if (n >= 10 && memcmp (probe, "ID3", 3) == 0) {
        size_t tag_size = 0;
        if (bf_syncsafe32 (probe + 6, &tag_size)) {
            size_t off = 10 + tag_size;
            if (off + 4 <= n && memcmp (probe + off, "fLaC", 4) == 0)
                return "FLAC audio (with ID3)";
        }
    }

    /* Ogg pages carry codec markers in packet data. Recognize the common
       Opus/Vorbis identification headers before the generic Ogg entry. */
    if (n >= 4 && memcmp (probe, "OggS", 4) == 0) {
        if (bf_contains (probe + 4, n - 4, "OpusHead"))
            return "Ogg Opus audio";
        if (bf_contains (probe + 4, n - 4, "\x01vorbis"))
            return "Ogg Vorbis audio";
    }

    /* EBML containers: upstream file(1) checks the EBML id and then the
       DocType field for webm/matroska. Keep the bash-os detector small by
       scanning only the existing probe window. */
    if (n >= 4 && memcmp (probe, "\x1a\x45\xdf\xa3", 4) == 0) {
        if (bf_contains (probe + 4, n - 4, "webm"))
            return "WebM video";
        if (bf_contains (probe + 4, n - 4, "matroska"))
            return "Matroska container";
        return "EBML container";
    }

    /* Mach-O universal/fat binary uses the same CAFEBABE prefix as Java
       class files. Treat only plausible nonzero fat architecture counts as
       Mach-O so ordinary Java class magic remains table-driven below. */
    if (n >= 8 && memcmp (probe, "\xca\xfe\xba\xbe", 4) == 0) {
        unsigned long nfat_arch = bf_be32 (probe + 4);
        if (nfat_arch >= 1 && nfat_arch <= 20)
            return "Mach-O universal binary";
    }

    /* FITS — file(1) (Magdir/images) matches the "SIMPLE  =" prefix but then
       requires two space bytes (0x2020) at offset 89 — the left padding of
       the 2nd card's value field — before declaring "FITS image data". The
       upstream comment is explicit that this guards against text/config files
       that merely begin with "SIMPLE  = ..." (e.g. a key=value line). A real
       FITS file is built from 80-byte cards padded to a 2880-byte block, so
       offset 89 lands in that padding and the check holds. */
    if (n >= 91 && memcmp (probe, "SIMPLE  =", 9) == 0 &&
        probe[89] == 0x20 && probe[90] == 0x20)
        return "FITS image data";

    for (size_t i = 0; i < BF_NSIGS; i++) {
        const bf_sig *s = &bf_table[i];
        if ((size_t) (s->offset + s->len) > n) continue;
        if (memcmp (probe + s->offset, s->magic, (size_t) s->len) == 0)
            return s->desc;
    }

    size_t rem = 0;
    const unsigned char *trim = bf_skip_ws (probe, n, &rem);
    if (bf_starts_ci (trim, rem, "<!doctype html") ||
        bf_starts_ci (trim, rem, "<html"))
        return "HTML document";
    if (rem > 1 && (trim[0] == '{' || trim[0] == '['))
        return "JSON text data";

    if (n == 0) return "empty";
    if (bf_is_text (probe, n)) {
        int u = bf_utf8_classify (probe, n);
        if (u == 0) return "ASCII text";
        if (u == 1) return "UTF-8 text";
        return "ISO-8859 text";  /* invalid UTF-8 high bytes — file(1)-style fallback */
    }
    return "data";
}

static int
bf_is_iso9660 (int fd)
{
    unsigned char magic[5];

    if (lseek (fd, BF_ISO9660_MAGIC_OFFSET, SEEK_SET) < 0)
        return 0;
    return read (fd, magic, sizeof magic) == (ssize_t) sizeof magic &&
           memcmp (magic, "CD001", sizeof magic) == 0;
}

/* file(1) prints "LABEL: DESC", or just "DESC" with -b/--brief. */
#define BF_EMIT(label, desc) \
    do { if (brief) printf ("%s\n", (desc)); \
         else        printf ("%s: %s\n", (label), (desc)); } while (0)

int
file_builtin (WORD_LIST *list)
{
    int brief = 0;

    /* Leading options (file(1) subset). */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (strcmp (w, "--") == 0) { list = list->next; break; }
        if (strcmp (w, "--help") == 0) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-v") == 0) {
            puts ("file 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "-b") == 0 || strcmp (w, "--brief") == 0) {
            brief = 1; list = list->next; continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list) {
        builtin_error ("usage: file [-b] FILE [FILE...]");
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;

        /* "-" reads standard input; file(1) labels it "/dev/stdin". */
        if (strcmp (path, "-") == 0) {
            unsigned char probe[BF_PROBE_LEN];
            ssize_t n = read (STDIN_FILENO, probe, sizeof probe);
            if (n < 0) n = 0;
            BF_EMIT ("/dev/stdin", bf_classify (probe, (size_t) n));
            continue;
        }

        struct stat st;
        if (lstat (path, &st) < 0) {
            printf ("%s: cannot stat (%s)\n", path, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (S_ISDIR (st.st_mode))  { BF_EMIT (path, "directory");         continue; }
        if (S_ISLNK (st.st_mode))  { BF_EMIT (path, "symbolic link");     continue; }
        if (S_ISFIFO (st.st_mode)) { BF_EMIT (path, "named pipe (FIFO)"); continue; }
        if (S_ISSOCK (st.st_mode)) { BF_EMIT (path, "socket");            continue; }
        if (S_ISBLK (st.st_mode))  { BF_EMIT (path, "block special");     continue; }
        if (S_ISCHR (st.st_mode))  { BF_EMIT (path, "character special"); continue; }
        if (!S_ISREG (st.st_mode)) { BF_EMIT (path, "special file");      continue; }
        int fd = open (path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            printf ("%s: cannot open (%s)\n", path, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        unsigned char probe[BF_PROBE_LEN];
        ssize_t n = read (fd, probe, sizeof probe);
        if (n < 0) {
            close (fd);
            printf ("%s: read error (%s)\n", path, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        const char *desc = bf_classify (probe, (size_t) n);
        if (strcmp (desc, "data") == 0 && bf_is_iso9660 (fd))
            desc = "ISO 9660 CD-ROM filesystem data";
        close (fd);
        BF_EMIT (path, desc);
    }
    return rc;
}

char *file_doc[] = {
    "Identify file types via magic-byte signatures.",
    "",
    "    file [-b] [--help|--version] FILE [FILE...]",
    "",
    "    -b, --brief    do not prepend `FILE: ' (print the type only)",
    "    --help         show this help",
    "    -v, --version  show version",
    "",
    "A FILE of `-' reads standard input (reported as /dev/stdin).",
    "",
    "Reads the first 512 bytes of each FILE and matches against a",
    "curated table of signatures: ELF, MS-DOS executable, gzip/zlib/compress/xz/zstd/lz4/lzip/lzop/lrzip/snappy-framed/bzip2, zip/7z/tar/deb/cabinet/wim/zim/CRX/xar/squashfs/",
    "cpio/cpio-crc/ar/rpm, scripts (#!), Java class, Java serialization, Dalvik DEX, OLE2 compound document, Mach-O, Mach-O universal/fat binary, LLVM bitcode, GNU message catalog, DICOM, LUKS encrypted file, DOS/MBR boot sector, pcap/pcapng, WebAssembly,",
    "Lua bytecode, Blender3D, QOI, MIDI, iNES ROM, Game Boy ROM, Apple binary plist, QEMU QCOW/VMware VMDK image, KeePass KDBX, OpenEXR, Git pack,",
    "JPEG/PNG/GIF/BMP/TIFF/BigTIFF/PSD/PCX/XCF/JP2/JPEG XL/BPG/FLIF/Netpbm/PAM, WebP/AIFF/AIFF-C/AU/Ogg/Opus/Vorbis/FLAC/MP3/FLV/SWF/MPEG, WebM/Matroska/MP4/AVIF,",
    "WOFF/WOFF2/TrueType/TrueType-collection (ttcf)/OpenType fonts, icns, AppleSingle/AppleDouble, age encrypted file, OpenSSH private key, PEM certificate, CBOR data, DjVu document, Erlang BEAM, Python bytecode,",
    "ISO9660, PDF, PostScript, RTF, vCard, iCalendar, UTF BOM text, SQLite, Microsoft Access, GDBM, FITS, HDF5, Parquet, Avro, ORC, XML, HTML, JSON, plus an ASCII / UTF-8 / ISO-8859 / data fallback.",
    "",
    "Output: `FILE: TYPE-DESCRIPTION` (one line per FILE).",
    (char *)NULL
};

struct builtin file_struct = {
    "file",
    file_builtin,
    BUILTIN_ENABLED,
    file_doc,
    "file [--help|--version] FILE [FILE...]",
    0
};
