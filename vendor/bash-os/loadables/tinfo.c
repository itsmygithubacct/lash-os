/* SPDX-License-Identifier: MIT */
/* tinfo.c — compiled terminfo reader for bash-os ncurses-input phase 1.
 *
 * Reads directory-tree compiled terminfo entries and exposes a tiny
 * tiget* shaped surface:
 *
 *   tinfo getstr CAP [TERM]
 *   tinfo getnum CAP [TERM]
 *   tinfo getflag CAP [TERM]
 *
 * Supported file formats:
 *   - legacy magic 0x011A, 16-bit number table
 *   - ncurses 6.1 magic 0x021E, 32-bit number table
 *   - ncurses extended-capability trailer for named booleans, numbers,
 *     and strings
 *
 * This loadable deliberately does not decode keys or manage ESC timing.
 * Phase 2's bashkgetch owns trie matching and must preserve the 50 ms
 * ESC grace / 400 ms CSI budget invariants from _bl_key.
 *
 * Source docs: research/bash-os/PROPOSAL_NCURSES_INPUT.md and
 * ncurses term(5).
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "loadables.h"

#define BT_MAGIC_LEGACY 0x011a
#define BT_MAGIC_32BIT  0x021e
#define BT_ABSENT16     (-1)
#define BT_CANCEL16     (-2)
#define BT_MAX_FILE     (512 * 1024)

typedef struct {
  const unsigned char *data;
  size_t len;
  int magic;

  const unsigned char *bools;
  int nbools;
  const unsigned char *nums;
  int nnums;
  const unsigned char *stridx;
  int nstrs;
  const unsigned char *strtab;
  int strtab_len;

  const unsigned char *ext_bools;
  int next_bools;
  const unsigned char *ext_nums;
  int next_nums;
  const unsigned char *ext_stridx;
  int next_strs;
  const unsigned char *ext_strtab;
  int ext_strtab_len;
  int ext_names_off;
} bt_entry;

typedef struct { const char *name; int idx; } bt_capidx;

static const bt_capidx bt_bool_caps[] = {
  { "auto_left_margin", 0 }, { "bw", 0 },
  { "auto_right_margin", 1 }, { "am", 1 },
  { "no_esc_ctlc", 2 }, { "xsb", 2 },
  { "ceol_standout_glitch", 3 }, { "xhp", 3 },
  { "eat_newline_glitch", 4 }, { "xenl", 4 },
  { "erase_overstrike", 5 }, { "eo", 5 },
  { "generic_type", 6 }, { "gn", 6 },
  { "hard_copy", 7 }, { "hc", 7 },
  { "has_meta_key", 8 }, { "km", 8 },
  { "has_status_line", 9 }, { "hs", 9 },
  { "insert_null_glitch", 10 }, { "in", 10 },
  { "memory_above", 11 }, { "da", 11 },
  { "memory_below", 12 }, { "db", 12 },
  { "move_insert_mode", 13 }, { "mir", 13 },
  { "move_standout_mode", 14 }, { "msgr", 14 },
  { "over_strike", 15 }, { "os", 15 },
  { "status_line_esc_ok", 16 }, { "eslok", 16 },
  { "dest_tabs_magic_smso", 17 }, { "xt", 17 },
  { "tilde_glitch", 18 }, { "hz", 18 },
  { "transparent_underline", 19 }, { "ul", 19 },
  { "xon_xoff", 20 }, { "xon", 20 },
  { "needs_xon_xoff", 21 }, { "nxon", 21 },
  { "prtr_silent", 22 }, { "mc5i", 22 },
  { "hard_cursor", 23 }, { "chts", 23 },
  { "non_rev_rmcup", 24 }, { "nrrmc", 24 },
  { "no_pad_char", 25 }, { "npc", 25 },
  { "non_dest_scroll_region", 26 }, { "ndscr", 26 },
  { "can_change", 27 }, { "ccc", 27 },
  { "back_color_erase", 28 }, { "bce", 28 },
  { "hue_lightness_saturation", 29 }, { "hls", 29 },
  { "col_addr_glitch", 30 }, { "xhpa", 30 },
  { "cr_cancels_micro_mode", 31 }, { "crxm", 31 },
  { "has_print_wheel", 32 }, { "daisy", 32 },
  { "row_addr_glitch", 33 }, { "xvpa", 33 },
  { "semi_auto_right_margin", 34 }, { "sam", 34 },
  { "cpi_changes_res", 35 }, { "cpix", 35 },
  { "lpi_changes_res", 36 }, { "lpix", 36 },
  { "backspaces_with_bs", 37 }, { "OTbs", 37 },
  { "crt_no_scrolling", 38 }, { "OTns", 38 },
  { "no_correctly_working_cr", 39 }, { "OTnc", 39 },
  { "gnu_has_meta_key", 40 }, { "OTMT", 40 },
  { "linefeed_is_newline", 41 }, { "OTNL", 41 },
  { "has_hardware_tabs", 42 }, { "OTpt", 42 },
  { "return_does_clr_eol", 43 }, { "OTxr", 43 },
  { NULL, -1 }
};

static const bt_capidx bt_num_caps[] = {
  { "columns", 0 }, { "cols", 0 },
  { "init_tabs", 1 }, { "it", 1 },
  { "lines", 2 },
  { "lines_of_memory", 3 }, { "lm", 3 },
  { "magic_cookie_glitch", 4 }, { "xmc", 4 },
  { "padding_baud_rate", 5 }, { "pb", 5 },
  { "virtual_terminal", 6 }, { "vt", 6 },
  { "width_status_line", 7 }, { "wsl", 7 },
  { "num_labels", 8 }, { "nlab", 8 },
  { "label_height", 9 }, { "lh", 9 },
  { "label_width", 10 }, { "lw", 10 },
  { "max_attributes", 11 }, { "ma", 11 },
  { "maximum_windows", 12 }, { "wnum", 12 },
  { "max_colors", 13 }, { "colors", 13 },
  { "max_pairs", 14 }, { "pairs", 14 },
  { "no_color_video", 15 }, { "ncv", 15 },
  { "buffer_capacity", 16 }, { "bufsz", 16 },
  { "dot_vert_spacing", 17 }, { "spinv", 17 },
  { "dot_horz_spacing", 18 }, { "spinh", 18 },
  { "max_micro_address", 19 }, { "maddr", 19 },
  { "max_micro_jump", 20 }, { "mjump", 20 },
  { "micro_col_size", 21 }, { "mcs", 21 },
  { "micro_line_size", 22 }, { "mls", 22 },
  { "number_of_pins", 23 }, { "npins", 23 },
  { "output_res_char", 24 }, { "orc", 24 },
  { "output_res_line", 25 }, { "orl", 25 },
  { "output_res_horz_inch", 26 }, { "orhi", 26 },
  { "output_res_vert_inch", 27 }, { "orvi", 27 },
  { "print_rate", 28 }, { "cps", 28 },
  { "wide_char_size", 29 }, { "widcs", 29 },
  { "buttons", 30 }, { "btns", 30 },
  { "bit_image_entwining", 31 }, { "bitwin", 31 },
  { "bit_image_type", 32 }, { "bitype", 32 },
  { "magic_cookie_glitch_ul", 33 }, { "OTug", 33 },
  { "carriage_return_delay", 34 }, { "OTdC", 34 },
  { "new_line_delay", 35 }, { "OTdN", 35 },
  { "backspace_delay", 36 }, { "OTdB", 36 },
  { "horizontal_tab_delay", 37 }, { "OTdT", 37 },
  { "number_of_function_keys", 38 }, { "OTkn", 38 },
  { NULL, -1 }
};

static const bt_capidx bt_str_caps[] = {
  { "back_tab", 0 }, { "cbt", 0 },
  { "bell", 1 }, { "bel", 1 },
  { "carriage_return", 2 }, { "cr", 2 },
  { "change_scroll_region", 3 }, { "csr", 3 },
  { "clear_all_tabs", 4 }, { "tbc", 4 },
  { "clear_screen", 5 }, { "clear", 5 },
  { "clr_eol", 6 }, { "el", 6 },
  { "clr_eos", 7 }, { "ed", 7 },
  { "column_address", 8 }, { "hpa", 8 },
  { "command_character", 9 }, { "cmdch", 9 },
  { "cursor_address", 10 }, { "cup", 10 },
  { "cursor_down", 11 }, { "cud1", 11 },
  { "cursor_home", 12 }, { "home", 12 },
  { "cursor_invisible", 13 }, { "civis", 13 },
  { "cursor_left", 14 }, { "cub1", 14 },
  { "cursor_mem_address", 15 }, { "mrcup", 15 },
  { "cursor_normal", 16 }, { "cnorm", 16 },
  { "cursor_right", 17 }, { "cuf1", 17 },
  { "cursor_to_ll", 18 }, { "ll", 18 },
  { "cursor_up", 19 }, { "cuu1", 19 },
  { "cursor_visible", 20 }, { "cvvis", 20 },
  { "delete_character", 21 }, { "dch1", 21 },
  { "delete_line", 22 }, { "dl1", 22 },
  { "dis_status_line", 23 }, { "dsl", 23 },
  { "down_half_line", 24 }, { "hd", 24 },
  { "enter_alt_charset_mode", 25 }, { "smacs", 25 },
  { "enter_blink_mode", 26 }, { "blink", 26 },
  { "enter_bold_mode", 27 }, { "bold", 27 },
  { "enter_ca_mode", 28 }, { "smcup", 28 },
  { "enter_delete_mode", 29 }, { "smdc", 29 },
  { "enter_dim_mode", 30 }, { "dim", 30 },
  { "enter_insert_mode", 31 }, { "smir", 31 },
  { "enter_secure_mode", 32 }, { "invis", 32 },
  { "enter_protected_mode", 33 }, { "prot", 33 },
  { "enter_reverse_mode", 34 }, { "rev", 34 },
  { "enter_standout_mode", 35 }, { "smso", 35 },
  { "enter_underline_mode", 36 }, { "smul", 36 },
  { "erase_chars", 37 }, { "ech", 37 },
  { "exit_alt_charset_mode", 38 }, { "rmacs", 38 },
  { "exit_attribute_mode", 39 }, { "sgr0", 39 },
  { "exit_ca_mode", 40 }, { "rmcup", 40 },
  { "exit_delete_mode", 41 }, { "rmdc", 41 },
  { "exit_insert_mode", 42 }, { "rmir", 42 },
  { "exit_standout_mode", 43 }, { "rmso", 43 },
  { "exit_underline_mode", 44 }, { "rmul", 44 },
  { "flash_screen", 45 }, { "flash", 45 },
  { "form_feed", 46 }, { "ff", 46 },
  { "from_status_line", 47 }, { "fsl", 47 },
  { "init_1string", 48 }, { "is1", 48 },
  { "init_2string", 49 }, { "is2", 49 },
  { "init_3string", 50 }, { "is3", 50 },
  { "init_file", 51 }, { "if", 51 },
  { "insert_character", 52 }, { "ich1", 52 },
  { "insert_line", 53 }, { "il1", 53 },
  { "insert_padding", 54 }, { "ip", 54 },
  { "key_backspace", 55 }, { "kbs", 55 },
  { "key_catab", 56 }, { "ktbc", 56 },
  { "key_clear", 57 }, { "kclr", 57 },
  { "key_ctab", 58 }, { "kctab", 58 },
  { "key_dc", 59 }, { "kdch1", 59 },
  { "key_dl", 60 }, { "kdl1", 60 },
  { "key_down", 61 }, { "kcud1", 61 },
  { "key_eic", 62 }, { "krmir", 62 },
  { "key_eol", 63 }, { "kel", 63 },
  { "key_eos", 64 }, { "ked", 64 },
  { "key_f0", 65 }, { "kf0", 65 },
  { "key_f1", 66 }, { "kf1", 66 },
  { "key_f10", 67 }, { "kf10", 67 },
  { "key_f2", 68 }, { "kf2", 68 },
  { "key_f3", 69 }, { "kf3", 69 },
  { "key_f4", 70 }, { "kf4", 70 },
  { "key_f5", 71 }, { "kf5", 71 },
  { "key_f6", 72 }, { "kf6", 72 },
  { "key_f7", 73 }, { "kf7", 73 },
  { "key_f8", 74 }, { "kf8", 74 },
  { "key_f9", 75 }, { "kf9", 75 },
  { "key_home", 76 }, { "khome", 76 },
  { "key_ic", 77 }, { "kich1", 77 },
  { "key_il", 78 }, { "kil1", 78 },
  { "key_left", 79 }, { "kcub1", 79 },
  { "key_ll", 80 }, { "kll", 80 },
  { "key_npage", 81 }, { "knp", 81 },
  { "key_ppage", 82 }, { "kpp", 82 },
  { "key_right", 83 }, { "kcuf1", 83 },
  { "key_sf", 84 }, { "kind", 84 },
  { "key_sr", 85 }, { "kri", 85 },
  { "key_stab", 86 }, { "khts", 86 },
  { "key_up", 87 }, { "kcuu1", 87 },
  { "keypad_local", 88 }, { "rmkx", 88 },
  { "keypad_xmit", 89 }, { "smkx", 89 },
  { "lab_f0", 90 }, { "lf0", 90 },
  { "lab_f1", 91 }, { "lf1", 91 },
  { "lab_f10", 92 }, { "lf10", 92 },
  { "lab_f2", 93 }, { "lf2", 93 },
  { "lab_f3", 94 }, { "lf3", 94 },
  { "lab_f4", 95 }, { "lf4", 95 },
  { "lab_f5", 96 }, { "lf5", 96 },
  { "lab_f6", 97 }, { "lf6", 97 },
  { "lab_f7", 98 }, { "lf7", 98 },
  { "lab_f8", 99 }, { "lf8", 99 },
  { "lab_f9", 100 }, { "lf9", 100 },
  { "meta_off", 101 }, { "rmm", 101 },
  { "meta_on", 102 }, { "smm", 102 },
  { "newline", 103 }, { "nel", 103 },
  { "pad_char", 104 }, { "pad", 104 },
  { "parm_dch", 105 }, { "dch", 105 },
  { "parm_delete_line", 106 }, { "dl", 106 },
  { "parm_down_cursor", 107 }, { "cud", 107 },
  { "parm_ich", 108 }, { "ich", 108 },
  { "parm_index", 109 }, { "indn", 109 },
  { "parm_insert_line", 110 }, { "il", 110 },
  { "parm_left_cursor", 111 }, { "cub", 111 },
  { "parm_right_cursor", 112 }, { "cuf", 112 },
  { "parm_rindex", 113 }, { "rin", 113 },
  { "parm_up_cursor", 114 }, { "cuu", 114 },
  { "pkey_key", 115 }, { "pfkey", 115 },
  { "pkey_local", 116 }, { "pfloc", 116 },
  { "pkey_xmit", 117 }, { "pfx", 117 },
  { "print_screen", 118 }, { "mc0", 118 },
  { "prtr_off", 119 }, { "mc4", 119 },
  { "prtr_on", 120 }, { "mc5", 120 },
  { "repeat_char", 121 }, { "rep", 121 },
  { "reset_1string", 122 }, { "rs1", 122 },
  { "reset_2string", 123 }, { "rs2", 123 },
  { "reset_3string", 124 }, { "rs3", 124 },
  { "reset_file", 125 }, { "rf", 125 },
  { "restore_cursor", 126 }, { "rc", 126 },
  { "row_address", 127 }, { "vpa", 127 },
  { "save_cursor", 128 }, { "sc", 128 },
  { "scroll_forward", 129 }, { "ind", 129 },
  { "scroll_reverse", 130 }, { "ri", 130 },
  { "set_attributes", 131 }, { "sgr", 131 },
  { "set_tab", 132 }, { "hts", 132 },
  { "set_window", 133 }, { "wind", 133 },
  { "tab", 134 }, { "ht", 134 },
  { "to_status_line", 135 }, { "tsl", 135 },
  { "underline_char", 136 }, { "uc", 136 },
  { "up_half_line", 137 }, { "hu", 137 },
  { "init_prog", 138 }, { "iprog", 138 },
  { "key_a1", 139 }, { "ka1", 139 },
  { "key_a3", 140 }, { "ka3", 140 },
  { "key_b2", 141 }, { "kb2", 141 },
  { "key_c1", 142 }, { "kc1", 142 },
  { "key_c3", 143 }, { "kc3", 143 },
  { "prtr_non", 144 }, { "mc5p", 144 },
  { "char_padding", 145 }, { "rmp", 145 },
  { "acs_chars", 146 }, { "acsc", 146 },
  { "plab_norm", 147 }, { "pln", 147 },
  { "key_btab", 148 }, { "kcbt", 148 },
  { "enter_xon_mode", 149 }, { "smxon", 149 },
  { "exit_xon_mode", 150 }, { "rmxon", 150 },
  { "enter_am_mode", 151 }, { "smam", 151 },
  { "exit_am_mode", 152 }, { "rmam", 152 },
  { "xon_character", 153 }, { "xonc", 153 },
  { "xoff_character", 154 }, { "xoffc", 154 },
  { "ena_acs", 155 }, { "enacs", 155 },
  { "label_on", 156 }, { "smln", 156 },
  { "label_off", 157 }, { "rmln", 157 },
  { "key_beg", 158 }, { "kbeg", 158 },
  { "key_cancel", 159 }, { "kcan", 159 },
  { "key_close", 160 }, { "kclo", 160 },
  { "key_command", 161 }, { "kcmd", 161 },
  { "key_copy", 162 }, { "kcpy", 162 },
  { "key_create", 163 }, { "kcrt", 163 },
  { "key_end", 164 }, { "kend", 164 },
  { "key_enter", 165 }, { "kent", 165 },
  { "key_exit", 166 }, { "kext", 166 },
  { "key_find", 167 }, { "kfnd", 167 },
  { "key_help", 168 }, { "khlp", 168 },
  { "key_mark", 169 }, { "kmrk", 169 },
  { "key_message", 170 }, { "kmsg", 170 },
  { "key_move", 171 }, { "kmov", 171 },
  { "key_next", 172 }, { "knxt", 172 },
  { "key_open", 173 }, { "kopn", 173 },
  { "key_options", 174 }, { "kopt", 174 },
  { "key_previous", 175 }, { "kprv", 175 },
  { "key_print", 176 }, { "kprt", 176 },
  { "key_redo", 177 }, { "krdo", 177 },
  { "key_reference", 178 }, { "kref", 178 },
  { "key_refresh", 179 }, { "krfr", 179 },
  { "key_replace", 180 }, { "krpl", 180 },
  { "key_restart", 181 }, { "krst", 181 },
  { "key_resume", 182 }, { "kres", 182 },
  { "key_save", 183 }, { "ksav", 183 },
  { "key_suspend", 184 }, { "kspd", 184 },
  { "key_undo", 185 }, { "kund", 185 },
  { "key_sbeg", 186 }, { "kBEG", 186 },
  { "key_scancel", 187 }, { "kCAN", 187 },
  { "key_scommand", 188 }, { "kCMD", 188 },
  { "key_scopy", 189 }, { "kCPY", 189 },
  { "key_screate", 190 }, { "kCRT", 190 },
  { "key_sdc", 191 }, { "kDC", 191 },
  { "key_sdl", 192 }, { "kDL", 192 },
  { "key_select", 193 }, { "kslt", 193 },
  { "key_send", 194 }, { "kEND", 194 },
  { "key_seol", 195 }, { "kEOL", 195 },
  { "key_sexit", 196 }, { "kEXT", 196 },
  { "key_sfind", 197 }, { "kFND", 197 },
  { "key_shelp", 198 }, { "kHLP", 198 },
  { "key_shome", 199 }, { "kHOM", 199 },
  { "key_sic", 200 }, { "kIC", 200 },
  { "key_sleft", 201 }, { "kLFT", 201 },
  { "key_smessage", 202 }, { "kMSG", 202 },
  { "key_smove", 203 }, { "kMOV", 203 },
  { "key_snext", 204 }, { "kNXT", 204 },
  { "key_soptions", 205 }, { "kOPT", 205 },
  { "key_sprevious", 206 }, { "kPRV", 206 },
  { "key_sprint", 207 }, { "kPRT", 207 },
  { "key_sredo", 208 }, { "kRDO", 208 },
  { "key_sreplace", 209 }, { "kRPL", 209 },
  { "key_sright", 210 }, { "kRIT", 210 },
  { "key_srsume", 211 }, { "kRES", 211 },
  { "key_ssave", 212 }, { "kSAV", 212 },
  { "key_ssuspend", 213 }, { "kSPD", 213 },
  { "key_sundo", 214 }, { "kUND", 214 },
  { "req_for_input", 215 }, { "rfi", 215 },
  { "key_f11", 216 }, { "kf11", 216 },
  { "key_f12", 217 }, { "kf12", 217 },
  { "key_f13", 218 }, { "kf13", 218 },
  { "key_f14", 219 }, { "kf14", 219 },
  { "key_f15", 220 }, { "kf15", 220 },
  { "key_f16", 221 }, { "kf16", 221 },
  { "key_f17", 222 }, { "kf17", 222 },
  { "key_f18", 223 }, { "kf18", 223 },
  { "key_f19", 224 }, { "kf19", 224 },
  { "key_f20", 225 }, { "kf20", 225 },
  { "key_f21", 226 }, { "kf21", 226 },
  { "key_f22", 227 }, { "kf22", 227 },
  { "key_f23", 228 }, { "kf23", 228 },
  { "key_f24", 229 }, { "kf24", 229 },
  { "key_f25", 230 }, { "kf25", 230 },
  { "key_f26", 231 }, { "kf26", 231 },
  { "key_f27", 232 }, { "kf27", 232 },
  { "key_f28", 233 }, { "kf28", 233 },
  { "key_f29", 234 }, { "kf29", 234 },
  { "key_f30", 235 }, { "kf30", 235 },
  { "key_f31", 236 }, { "kf31", 236 },
  { "key_f32", 237 }, { "kf32", 237 },
  { "key_f33", 238 }, { "kf33", 238 },
  { "key_f34", 239 }, { "kf34", 239 },
  { "key_f35", 240 }, { "kf35", 240 },
  { "key_f36", 241 }, { "kf36", 241 },
  { "key_f37", 242 }, { "kf37", 242 },
  { "key_f38", 243 }, { "kf38", 243 },
  { "key_f39", 244 }, { "kf39", 244 },
  { "key_f40", 245 }, { "kf40", 245 },
  { "key_f41", 246 }, { "kf41", 246 },
  { "key_f42", 247 }, { "kf42", 247 },
  { "key_f43", 248 }, { "kf43", 248 },
  { "key_f44", 249 }, { "kf44", 249 },
  { "key_f45", 250 }, { "kf45", 250 },
  { "key_f46", 251 }, { "kf46", 251 },
  { "key_f47", 252 }, { "kf47", 252 },
  { "key_f48", 253 }, { "kf48", 253 },
  { "key_f49", 254 }, { "kf49", 254 },
  { "key_f50", 255 }, { "kf50", 255 },
  { "key_f51", 256 }, { "kf51", 256 },
  { "key_f52", 257 }, { "kf52", 257 },
  { "key_f53", 258 }, { "kf53", 258 },
  { "key_f54", 259 }, { "kf54", 259 },
  { "key_f55", 260 }, { "kf55", 260 },
  { "key_f56", 261 }, { "kf56", 261 },
  { "key_f57", 262 }, { "kf57", 262 },
  { "key_f58", 263 }, { "kf58", 263 },
  { "key_f59", 264 }, { "kf59", 264 },
  { "key_f60", 265 }, { "kf60", 265 },
  { "key_f61", 266 }, { "kf61", 266 },
  { "key_f62", 267 }, { "kf62", 267 },
  { "key_f63", 268 }, { "kf63", 268 },
  { "clr_bol", 269 }, { "el1", 269 },
  { "clear_margins", 270 }, { "mgc", 270 },
  { "set_left_margin", 271 }, { "smgl", 271 },
  { "set_right_margin", 272 }, { "smgr", 272 },
  { "label_format", 273 }, { "fln", 273 },
  { "set_clock", 274 }, { "sclk", 274 },
  { "display_clock", 275 }, { "dclk", 275 },
  { "remove_clock", 276 }, { "rmclk", 276 },
  { "create_window", 277 }, { "cwin", 277 },
  { "goto_window", 278 }, { "wingo", 278 },
  { "hangup", 279 }, { "hup", 279 },
  { "dial_phone", 280 }, { "dial", 280 },
  { "quick_dial", 281 }, { "qdial", 281 },
  { "tone", 282 },
  { "pulse", 283 },
  { "flash_hook", 284 }, { "hook", 284 },
  { "fixed_pause", 285 }, { "pause", 285 },
  { "wait_tone", 286 }, { "wait", 286 },
  { "user0", 287 }, { "u0", 287 },
  { "user1", 288 }, { "u1", 288 },
  { "user2", 289 }, { "u2", 289 },
  { "user3", 290 }, { "u3", 290 },
  { "user4", 291 }, { "u4", 291 },
  { "user5", 292 }, { "u5", 292 },
  { "user6", 293 }, { "u6", 293 },
  { "user7", 294 }, { "u7", 294 },
  { "user8", 295 }, { "u8", 295 },
  { "user9", 296 }, { "u9", 296 },
  { "orig_pair", 297 }, { "op", 297 },
  { "orig_colors", 298 }, { "oc", 298 },
  { "initialize_color", 299 }, { "initc", 299 },
  { "initialize_pair", 300 }, { "initp", 300 },
  { "set_color_pair", 301 }, { "scp", 301 },
  { "set_foreground", 302 }, { "setf", 302 },
  { "set_background", 303 }, { "setb", 303 },
  { "change_char_pitch", 304 }, { "cpi", 304 },
  { "change_line_pitch", 305 }, { "lpi", 305 },
  { "change_res_horz", 306 }, { "chr", 306 },
  { "change_res_vert", 307 }, { "cvr", 307 },
  { "define_char", 308 }, { "defc", 308 },
  { "enter_doublewide_mode", 309 }, { "swidm", 309 },
  { "enter_draft_quality", 310 }, { "sdrfq", 310 },
  { "enter_italics_mode", 311 }, { "sitm", 311 },
  { "enter_leftward_mode", 312 }, { "slm", 312 },
  { "enter_micro_mode", 313 }, { "smicm", 313 },
  { "enter_near_letter_quality", 314 }, { "snlq", 314 },
  { "enter_normal_quality", 315 }, { "snrmq", 315 },
  { "enter_shadow_mode", 316 }, { "sshm", 316 },
  { "enter_subscript_mode", 317 }, { "ssubm", 317 },
  { "enter_superscript_mode", 318 }, { "ssupm", 318 },
  { "enter_upward_mode", 319 }, { "sum", 319 },
  { "exit_doublewide_mode", 320 }, { "rwidm", 320 },
  { "exit_italics_mode", 321 }, { "ritm", 321 },
  { "exit_leftward_mode", 322 }, { "rlm", 322 },
  { "exit_micro_mode", 323 }, { "rmicm", 323 },
  { "exit_shadow_mode", 324 }, { "rshm", 324 },
  { "exit_subscript_mode", 325 }, { "rsubm", 325 },
  { "exit_superscript_mode", 326 }, { "rsupm", 326 },
  { "exit_upward_mode", 327 }, { "rum", 327 },
  { "micro_column_address", 328 }, { "mhpa", 328 },
  { "micro_down", 329 }, { "mcud1", 329 },
  { "micro_left", 330 }, { "mcub1", 330 },
  { "micro_right", 331 }, { "mcuf1", 331 },
  { "micro_row_address", 332 }, { "mvpa", 332 },
  { "micro_up", 333 }, { "mcuu1", 333 },
  { "order_of_pins", 334 }, { "porder", 334 },
  { "parm_down_micro", 335 }, { "mcud", 335 },
  { "parm_left_micro", 336 }, { "mcub", 336 },
  { "parm_right_micro", 337 }, { "mcuf", 337 },
  { "parm_up_micro", 338 }, { "mcuu", 338 },
  { "select_char_set", 339 }, { "scs", 339 },
  { "set_bottom_margin", 340 }, { "smgb", 340 },
  { "set_bottom_margin_parm", 341 }, { "smgbp", 341 },
  { "set_left_margin_parm", 342 }, { "smglp", 342 },
  { "set_right_margin_parm", 343 }, { "smgrp", 343 },
  { "set_top_margin", 344 }, { "smgt", 344 },
  { "set_top_margin_parm", 345 }, { "smgtp", 345 },
  { "start_bit_image", 346 }, { "sbim", 346 },
  { "start_char_set_def", 347 }, { "scsd", 347 },
  { "stop_bit_image", 348 }, { "rbim", 348 },
  { "stop_char_set_def", 349 }, { "rcsd", 349 },
  { "subscript_characters", 350 }, { "subcs", 350 },
  { "superscript_characters", 351 }, { "supcs", 351 },
  { "these_cause_cr", 352 }, { "docr", 352 },
  { "zero_motion", 353 }, { "zerom", 353 },
  { "char_set_names", 354 }, { "csnm", 354 },
  { "key_mouse", 355 }, { "kmous", 355 },
  { "mouse_info", 356 }, { "minfo", 356 },
  { "req_mouse_pos", 357 }, { "reqmp", 357 },
  { "get_mouse", 358 }, { "getm", 358 },
  { "set_a_foreground", 359 }, { "setaf", 359 },
  { "set_a_background", 360 }, { "setab", 360 },
  { "pkey_plab", 361 }, { "pfxl", 361 },
  { "device_type", 362 }, { "devt", 362 },
  { "code_set_init", 363 }, { "csin", 363 },
  { "set0_des_seq", 364 }, { "s0ds", 364 },
  { "set1_des_seq", 365 }, { "s1ds", 365 },
  { "set2_des_seq", 366 }, { "s2ds", 366 },
  { "set3_des_seq", 367 }, { "s3ds", 367 },
  { "set_lr_margin", 368 }, { "smglr", 368 },
  { "set_tb_margin", 369 }, { "smgtb", 369 },
  { "bit_image_repeat", 370 }, { "birep", 370 },
  { "bit_image_newline", 371 }, { "binel", 371 },
  { "bit_image_carriage_return", 372 }, { "bicr", 372 },
  { "color_names", 373 }, { "colornm", 373 },
  { "define_bit_image_region", 374 }, { "defbi", 374 },
  { "end_bit_image_region", 375 }, { "endbi", 375 },
  { "set_color_band", 376 }, { "setcolor", 376 },
  { "set_page_length", 377 }, { "slines", 377 },
  { "display_pc_char", 378 }, { "dispc", 378 },
  { "enter_pc_charset_mode", 379 }, { "smpch", 379 },
  { "exit_pc_charset_mode", 380 }, { "rmpch", 380 },
  { "enter_scancode_mode", 381 }, { "smsc", 381 },
  { "exit_scancode_mode", 382 }, { "rmsc", 382 },
  { "pc_term_options", 383 }, { "pctrm", 383 },
  { "scancode_escape", 384 }, { "scesc", 384 },
  { "alt_scancode_esc", 385 }, { "scesa", 385 },
  { "enter_horizontal_hl_mode", 386 }, { "ehhlm", 386 },
  { "enter_left_hl_mode", 387 }, { "elhlm", 387 },
  { "enter_low_hl_mode", 388 }, { "elohlm", 388 },
  { "enter_right_hl_mode", 389 }, { "erhlm", 389 },
  { "enter_top_hl_mode", 390 }, { "ethlm", 390 },
  { "enter_vertical_hl_mode", 391 }, { "evhlm", 391 },
  { "set_a_attributes", 392 }, { "sgr1", 392 },
  { "set_pglen_inch", 393 }, { "slength", 393 },
  { "termcap_init2", 394 }, { "OTi2", 394 },
  { "termcap_reset", 395 }, { "OTrs", 395 },
  { "linefeed_if_not_lf", 396 }, { "OTnl", 396 },
  { "backspace_if_not_bs", 397 }, { "OTbc", 397 },
  { "other_non_function_keys", 398 }, { "OTko", 398 },
  { "arrow_key_map", 399 }, { "OTma", 399 },
  { "acs_ulcorner", 400 }, { "OTG2", 400 },
  { "acs_llcorner", 401 }, { "OTG3", 401 },
  { "acs_urcorner", 402 }, { "OTG1", 402 },
  { "acs_lrcorner", 403 }, { "OTG4", 403 },
  { "acs_ltee", 404 }, { "OTGR", 404 },
  { "acs_rtee", 405 }, { "OTGL", 405 },
  { "acs_btee", 406 }, { "OTGU", 406 },
  { "acs_ttee", 407 }, { "OTGD", 407 },
  { "acs_hline", 408 }, { "OTGH", 408 },
  { "acs_vline", 409 }, { "OTGV", 409 },
  { "acs_plus", 410 }, { "OTGC", 410 },
  { "memory_lock", 411 }, { "meml", 411 },
  { "memory_unlock", 412 }, { "memu", 412 },
  { "box_chars_1", 413 }, { "box1", 413 },
  { NULL, -1 }
};

static int
bt_u16 (const unsigned char *p)
{
  return (int) ((unsigned int) p[0] | ((unsigned int) p[1] << 8));
}

static int
bt_s16 (const unsigned char *p)
{
  uint16_t u = (uint16_t) bt_u16 (p);
  return (int) (int16_t) u;
}

static int32_t
bt_s32 (const unsigned char *p)
{
  uint32_t u = (uint32_t) p[0]
             | ((uint32_t) p[1] << 8)
             | ((uint32_t) p[2] << 16)
             | ((uint32_t) p[3] << 24);
  return (int32_t) u;
}

static int
bt_lookup (const bt_capidx *caps, const char *name)
{
  for (int i = 0; caps[i].name; i++)
    if (strcmp (caps[i].name, name) == 0)
      return caps[i].idx;
  return -1;
}

static int
bt_is_dir (const char *path)
{
  struct stat st;
  return stat (path, &st) == 0 && S_ISDIR (st.st_mode);
}

static int
bt_read_file (const char *path, unsigned char **out, size_t *out_len)
{
  FILE *fp = fopen (path, "rb");
  if (!fp) return -1;
  if (fseek (fp, 0, SEEK_END) < 0)
    { fclose (fp); return -1; }
  long n = ftell (fp);
  if (n < 0 || n > BT_MAX_FILE)
    { fclose (fp); errno = EFBIG; return -1; }
  rewind (fp);
  unsigned char *buf = malloc ((size_t) n ? (size_t) n : 1);
  if (!buf) { fclose (fp); errno = ENOMEM; return -1; }
  size_t got = fread (buf, 1, (size_t) n, fp);
  int saved = ferror (fp) ? errno : 0;
  fclose (fp);
  if (got != (size_t) n)
    { free (buf); errno = saved ? saved : EIO; return -1; }
  *out = buf;
  *out_len = got;
  return 0;
}

static int
bt_try_path (const char *path, unsigned char **out, size_t *out_len)
{
  if (!path || !*path) return -1;
  return bt_read_file (path, out, out_len);
}

static int
bt_try_dir (const char *dir, const char *term, unsigned char **out, size_t *out_len)
{
  if (!dir || !*dir || !term || !*term) return -1;
  char path[1024];
  unsigned char c = (unsigned char) term[0];
  if (snprintf (path, sizeof path, "%s/%c/%s", dir, c, term) < (int) sizeof path
      && bt_read_file (path, out, out_len) == 0)
    return 0;
  if (snprintf (path, sizeof path, "%s/%02x/%s", dir, c, term) < (int) sizeof path
      && bt_read_file (path, out, out_len) == 0)
    return 0;
  return -1;
}

static int
bt_load_term (const char *term, unsigned char **out, size_t *out_len)
{
  const char *override = getenv ("BASHTINFO_PATH");
  if (override && *override)
    {
      if (bt_is_dir (override))
        {
          if (bt_try_dir (override, term, out, out_len) == 0) return 0;
        }
      else if (bt_try_path (override, out, out_len) == 0)
        return 0;
    }

  const char *terminfo = getenv ("TERMINFO");
  if (terminfo && *terminfo && bt_try_dir (terminfo, term, out, out_len) == 0)
    return 0;

  const char *dirs = getenv ("TERMINFO_DIRS");
  if (dirs && *dirs)
    {
      char *copy = strdup (dirs);
      if (copy)
        {
          char *save = NULL;
          for (char *d = strtok_r (copy, ":", &save); d; d = strtok_r (NULL, ":", &save))
            {
              if (*d == '\0') d = "/usr/share/terminfo";
              if (bt_try_dir (d, term, out, out_len) == 0)
                { free (copy); return 0; }
            }
          free (copy);
        }
    }

  static const char *common[] = {
    "/usr/share/terminfo", "/lib/terminfo", "/etc/terminfo",
    "/usr/lib/terminfo", "/boot/system/data/terminfo", NULL
  };
  for (int i = 0; common[i]; i++)
    if (bt_try_dir (common[i], term, out, out_len) == 0)
      return 0;
  return -1;
}

static int
bt_parse (const unsigned char *buf, size_t len, bt_entry *e)
{
  memset (e, 0, sizeof *e);
  if (len < 12) return -1;

  int magic = bt_u16 (buf);
  if (magic != BT_MAGIC_LEGACY && magic != BT_MAGIC_32BIT) return -1;
  int names = bt_s16 (buf + 2);
  int nbools = bt_s16 (buf + 4);
  int nnums = bt_s16 (buf + 6);
  int nstrs = bt_s16 (buf + 8);
  int strtab_len = bt_s16 (buf + 10);
  if (names < 0 || nbools < 0 || nnums < 0 || nstrs < 0 || strtab_len < 0)
    return -1;

  size_t off = 12;
  if (off + (size_t) names > len) return -1;
  off += (size_t) names;

  if (off + (size_t) nbools > len) return -1;
  e->bools = buf + off;
  e->nbools = nbools;
  off += (size_t) nbools;

  if (off & 1) off++;

  size_t num_size = (magic == BT_MAGIC_32BIT) ? 4 : 2;
  if (off + (size_t) nnums * num_size > len) return -1;
  e->nums = buf + off;
  e->nnums = nnums;
  off += (size_t) nnums * num_size;

  if (off + (size_t) nstrs * 2 > len) return -1;
  e->stridx = buf + off;
  e->nstrs = nstrs;
  off += (size_t) nstrs * 2;

  if (off + (size_t) strtab_len > len) return -1;
  e->strtab = buf + off;
  e->strtab_len = strtab_len;
  off += (size_t) strtab_len;

  if (off & 1) off++;

  e->data = buf;
  e->len = len;
  e->magic = magic;

  if (off + 10 <= len)
    {
      int xb = bt_s16 (buf + off + 0);
      int xn = bt_s16 (buf + off + 2);
      int xs = bt_s16 (buf + off + 4);
      int xt_items = bt_s16 (buf + off + 6);
      int xt_len = bt_s16 (buf + off + 8);
      if (xb >= 0 && xn >= 0 && xs >= 0 && xt_items >= xb + xn + xs && xt_len >= 0)
        {
          size_t p = off + 10;
          if (p + (size_t) xb > len) return 0;
          e->ext_bools = buf + p;
          e->next_bools = xb;
          p += (size_t) xb;
          if (p & 1) p++;

          if (p + (size_t) xn * num_size > len) return 0;
          e->ext_nums = buf + p;
          e->next_nums = xn;
          p += (size_t) xn * num_size;

          if (p + (size_t) xs * 2 > len) return 0;
          e->ext_stridx = buf + p;
          e->next_strs = xs;
          p += (size_t) xs * 2;

          if (p + (size_t) xt_len > len) return 0;
          e->ext_strtab = buf + p;
          e->ext_strtab_len = xt_len;
          e->ext_names_off = -1;

          int seen = 0;
          size_t q = 0;
          while (q < (size_t) xt_len && seen < xs)
            {
              size_t start = q;
              while (q < (size_t) xt_len && e->ext_strtab[q] != '\0') q++;
              if (q >= (size_t) xt_len) break;
              (void) start;
              q++;
              seen++;
            }
          if (seen == xs && q < (size_t) xt_len)
            e->ext_names_off = (int) q;
        }
    }

  return 0;
}

static int
bt_get_num_at (const bt_entry *e, int idx, int ext, int32_t *out)
{
  const unsigned char *base = ext ? e->ext_nums : e->nums;
  int count = ext ? e->next_nums : e->nnums;
  if (idx < 0 || idx >= count || !base) return -1;
  int32_t v = (e->magic == BT_MAGIC_32BIT)
            ? bt_s32 (base + (size_t) idx * 4)
            : (int32_t) bt_s16 (base + (size_t) idx * 2);
  if (v == BT_ABSENT16 || v == BT_CANCEL16) return -1;
  *out = v;
  return 0;
}

static int
bt_get_str_at (const bt_entry *e, int idx, int ext, const char **out)
{
  const unsigned char *idxbase = ext ? e->ext_stridx : e->stridx;
  const unsigned char *strtab = ext ? e->ext_strtab : e->strtab;
  int count = ext ? e->next_strs : e->nstrs;
  int tablen = ext ? e->ext_strtab_len : e->strtab_len;
  if (idx < 0 || idx >= count || !idxbase || !strtab) return -1;
  int off = bt_s16 (idxbase + (size_t) idx * 2);
  if (off == BT_ABSENT16 || off == BT_CANCEL16 || off < 0 || off >= tablen)
    return -1;
  *out = (const char *) strtab + off;
  return 0;
}

static int
bt_ext_name_index (const bt_entry *e, const char *name, int kind)
{
  if (!e->ext_strtab || e->ext_names_off < 0) return -1;
  int total = e->next_bools + e->next_nums + e->next_strs;
  int want_start = kind == 0 ? 0 : (kind == 1 ? e->next_bools : e->next_bools + e->next_nums);
  int want_count = kind == 0 ? e->next_bools : (kind == 1 ? e->next_nums : e->next_strs);
  size_t q = (size_t) e->ext_names_off;
  for (int i = 0; i < total && q < (size_t) e->ext_strtab_len; i++)
    {
      const char *s = (const char *) e->ext_strtab + q;
      size_t n = strnlen (s, (size_t) e->ext_strtab_len - q);
      if (q + n >= (size_t) e->ext_strtab_len) break;
      if (i >= want_start && i < want_start + want_count && strcmp (s, name) == 0)
        return i - want_start;
      q += n + 1;
    }
  return -1;
}

static int
bt_get_flag (const bt_entry *e, const char *name, int *out)
{
  int idx = bt_lookup (bt_bool_caps, name);
  if (idx >= 0)
    {
      if (idx >= e->nbools) return -1;
      int v = e->bools[idx];
      if (v == 0 || v == 1) { *out = v; return 0; }
      return -1;
    }
  idx = bt_ext_name_index (e, name, 0);
  if (idx >= 0 && idx < e->next_bools)
    {
      int v = e->ext_bools[idx];
      if (v == 0 || v == 1) { *out = v; return 0; }
    }
  return -1;
}

static int
bt_get_num (const bt_entry *e, const char *name, int32_t *out)
{
  int idx = bt_lookup (bt_num_caps, name);
  if (idx >= 0) return bt_get_num_at (e, idx, 0, out);
  idx = bt_ext_name_index (e, name, 1);
  if (idx >= 0) return bt_get_num_at (e, idx, 1, out);
  return -1;
}

static int
bt_get_str (const bt_entry *e, const char *name, const char **out)
{
  int idx = bt_lookup (bt_str_caps, name);
  if (idx >= 0) return bt_get_str_at (e, idx, 0, out);
  idx = bt_ext_name_index (e, name, 2);
  if (idx >= 0) return bt_get_str_at (e, idx, 1, out);
  return -1;
}

static void
bt_emit_escaped (const char *s)
{
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      switch (*p)
        {
        case 033: fputs ("\\E", stdout); break;
        case '\n': fputs ("\\n", stdout); break;
        case '\r': fputs ("\\r", stdout); break;
        case '\t': fputs ("\\t", stdout); break;
        case '\\': fputs ("\\\\", stdout); break;
        default:
          if (*p < 0x20 || *p == 0x7f)
            printf ("\\x%02x", *p);
          else
            putchar (*p);
        }
    }
}

static int
bt_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("usage: tinfo getstr|getnum|getflag CAP [TERM]"); return EX_USAGE; }
  const char *verb = args->word->word;
  const char *cap = args->next->word->word;
  const char *term = (args->next->next && args->next->next->word)
                   ? args->next->next->word->word
                   : getenv ("TERM");
  if (!term || !*term) term = "xterm-256color";

  unsigned char *buf = NULL;
  size_t len = 0;
  if (bt_load_term (term, &buf, &len) < 0)
    { builtin_error ("tinfo: terminfo entry not found for %s", term); return EXECUTION_FAILURE; }

  bt_entry e;
  if (bt_parse (buf, len, &e) < 0)
    { free (buf); builtin_error ("tinfo: invalid terminfo entry"); return EXECUTION_FAILURE; }

  int rc = EXECUTION_SUCCESS;
  if (strcmp (verb, "getstr") == 0)
    {
      const char *s = NULL;
      if (bt_get_str (&e, cap, &s) == 0)
        { bt_emit_escaped (s); putchar ('\n'); }
      else
        rc = EXECUTION_FAILURE;
    }
  else if (strcmp (verb, "getnum") == 0)
    {
      int32_t v;
      if (bt_get_num (&e, cap, &v) == 0)
        printf ("%ld\n", (long) v);
      else
        rc = EXECUTION_FAILURE;
    }
  else if (strcmp (verb, "getflag") == 0)
    {
      int v;
      if (bt_get_flag (&e, cap, &v) == 0)
        printf ("%d\n", v);
      else
        rc = EXECUTION_FAILURE;
    }
  else
    {
      builtin_error ("tinfo: unknown verb: %s", verb);
      rc = EX_USAGE;
    }

  free (buf);
  return rc;
}

int
tinfo_builtin (WORD_LIST *list)
{
  if (list && list->next == 0)
    {
      const char *w = list->word->word;
      if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("tinfo 0.1 (bash-loadable)"); return EXECUTION_SUCCESS; }
    }
  return bt_cmd (list);
}

char *tinfo_doc[] = {
  "Read compiled terminfo entries.",
  "",
  "    tinfo getstr CAP [TERM]     print string capability, escaped",
  "    tinfo getnum CAP [TERM]     print numeric capability",
  "    tinfo getflag CAP [TERM]    print 0 or 1 boolean capability",
  "",
  "TERM defaults to $TERM or xterm-256color. BASHTINFO_PATH may name a",
  "compiled terminfo file or a terminfo directory tree. TERMINFO and",
  "TERMINFO_DIRS are honored after BASHTINFO_PATH.",
  "",
  "Parses legacy 0x011A, ncurses 0x021E 32-bit-number entries, and",
  "the ncurses extended-capability trailer.",
  (char *)NULL
};

struct builtin tinfo_struct = {
  "tinfo",
  tinfo_builtin,
  BUILTIN_ENABLED,
  tinfo_doc,
  "tinfo getstr|getnum|getflag CAP [TERM]",
  0
};
