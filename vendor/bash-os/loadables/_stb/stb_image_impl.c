/* stb_image_impl.c — single implementation unit for the vendored stb_image
 * decoder (public domain, http://nothings.org/stb). bashtiv.c includes only
 * the header (declarations); the implementation lives here, once.
 *
 * Trimmed to the formats a terminal image viewer needs (PNG/JPEG/GIF/BMP/TGA)
 * to keep the statically-linked bash binary lean — HDR/PSD/PIC/PNM are
 * excluded. patch-bash-loadables.sh flattens `_stb/stb_image.h` to
 * `builtins/_stb_stb_image.h` and rewrites the include below to match.
 */
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_GIF
#define STBI_ONLY_BMP
#define STBI_ONLY_TGA
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#include "stb_image.h"
