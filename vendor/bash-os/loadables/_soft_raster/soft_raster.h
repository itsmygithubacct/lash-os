#ifndef SOFT_RASTER_H
#define SOFT_RASTER_H

/*
 * A small software rasterizer for 32-bit framebuffers: anti-aliased
 * primitives, two embedded bitmap fonts, sprite blits, and a letterbox
 * scaler.  Extracted from the software renderer shared by the
 * terminal-lander family of terminal games.
 *
 * The library is pure ISO C11 with no operating-system dependencies.
 * Drawing uses memory the canvas already owns and is fully clipped to the
 * canvas bounds.  sr_fill_polygon() uses a small stack workspace for ordinary
 * outlines and may allocate crossings for more than 64 vertices.
 *
 * Pixel format
 * ------------
 * A canvas is a row-major array of uint32_t pixels laid out as 0xAARRGGBB:
 *
 * - Colors passed to drawing calls are 0x00RRGGBB; the high byte of a color
 *   argument is ignored.
 * - sr_clear() and sr_px() store the color with alpha 0xFF (opaque).
 * - sr_blend() and every primitive built on it move the RGB channels toward
 *   the requested color by the effective coverage and saturate the alpha
 *   byte toward 0xFF by the same coverage.  Coverage is quantized to 1/256
 *   steps with the same fixed-point math the games use, so results on an
 *   opaque canvas are byte-identical to the original renderers.
 * - On a canvas that starts fully transparent (sr_canvas_init() zeroes the
 *   pixels), drawing therefore builds a premultiplied-alpha sprite: RGB
 *   carries color scaled by coverage and the high byte carries coverage.
 *   sr_blit_alpha(), sr_blit_tint(), sr_blit_scaled(), and
 *   sr_blit_transformed() composite such sprites over another canvas using
 *   that per-pixel alpha.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SR_VERSION_MAJOR 0
#define SR_VERSION_MINOR 5
#define SR_VERSION_PATCH 0

/* Embedded font glyph cell, before scaling. */
#define SR_FONT_W 8
#define SR_FONT_H 16

typedef struct sr_canvas {
    uint32_t *px;  /* row-major 0xAARRGGBB, px[y * w + x] */
    int w;
    int h;
    int clip_x0;
    int clip_y0;
    int clip_x1;
    int clip_y1;
    bool owns_px;  /* set by sr_canvas_init, cleared by sr_canvas_wrap */
} sr_canvas;

/*
 * Whole-canvas sprite transforms.  The bit values and operation order match
 * Tiled's orthogonal/isometric tile flags: exchange x/y first, then flip the
 * transformed image horizontally and vertically.  A diagonal exchange swaps
 * the output width and height.
 */
enum {
    SR_TRANSFORM_FLIP_HORIZONTAL = UINT8_C(1) << 0,
    SR_TRANSFORM_FLIP_VERTICAL = UINT8_C(1) << 1,
    SR_TRANSFORM_FLIP_DIAGONAL = UINT8_C(1) << 2
};

/*
 * Canvas lifetime
 * ---------------
 * sr_canvas_init() allocates w*h pixels, zeroed to transparent black
 * (0x00000000).  It fails (returns false, leaves *c zeroed) when w or h is
 * not positive, when the pixel count would overflow an int or the byte
 * count a size_t, or when allocation fails.
 *
 * sr_canvas_wrap() points the canvas at caller-owned memory of at least
 * w*h pixels without copying or clearing. Invalid dimensions leave an empty
 * canvas. sr_canvas_free() releases memory obtained by sr_canvas_init() and
 * never frees wrapped memory; either way it resets *c to an empty canvas.
 * Initialize or wrap only an empty/uninitialized canvas; free a live canvas
 * before reusing the struct, because replacing it does not release old pixels.
 */
bool sr_canvas_init(sr_canvas *c, int w, int h);
void sr_canvas_wrap(sr_canvas *c, uint32_t *mem, int w, int h);
void sr_canvas_free(sr_canvas *c);
void sr_canvas_set_clip(sr_canvas *c, int x, int y, int w, int h);
void sr_canvas_reset_clip(sr_canvas *c);

/* Convert the canvas into portable channel order for presentation APIs.
 * byte_count must cover w*h*4 or w*h*3 bytes respectively, and the output
 * must not overlap the canvas pixel storage. */
bool sr_pack_rgba(const sr_canvas *c, uint8_t *rgba, size_t byte_count);
bool sr_pack_rgb(const sr_canvas *c, uint8_t *rgb, size_t byte_count);

/* Color helpers: pack channels, linear mix by t in [0,1], multiply by k in
 * [0,2] with per-channel saturation. NaN factors clamp to the lower bound. */
uint32_t sr_rgb(uint8_t r, uint8_t g, uint8_t b);
uint32_t sr_mix(uint32_t a, uint32_t b, float t);
uint32_t sr_scale_rgb(uint32_t rgb, float k);

/* Pixels.  sr_px() is a clipped opaque store; sr_blend() applies the
 * fixed-point coverage blend described above.  alpha outside [0,1] is
 * clamped. */
void sr_clear(sr_canvas *c, uint32_t rgb);
void sr_px(sr_canvas *c, int x, int y, uint32_t rgb);
void sr_blend(sr_canvas *c, int x, int y, uint32_t rgb, float alpha);

/*
 * Primitives.  Coordinates are floats measured in pixels; edges that fall
 * between pixel centers receive fractional-coverage anti-aliasing.
 *
 * - sr_fill_rect: axis-aligned rectangle with AA edges.
 * - sr_stroke_rect: rectangle outline built from four filled bars of the
 *   given line width.
 * - sr_fill_circle: filled disc with an anti-aliased rim.
 * - sr_ring: circle outline of the given stroke width, anti-aliased on
 *   both sides.
 * - sr_line: stroked segment of the given width with round caps, coverage
 *   computed from the distance to the segment.  dash_on/dash_off give the
 *   dash pattern in pixels along the line; pass 0, 0 for a solid line.
 * - sr_fill_triangle: filled triangle via edge functions (either winding).
 *
 * sr_fill_triangle, sr_fill_convex and sr_fill_polygon sample the pixel
 * center rather than computing coverage, so their edges are hard. Non-finite
 * geometry is rejected as a no-op.
 */
void sr_fill_rect(sr_canvas *c, float x, float y, float w, float h,
                  uint32_t rgb, float alpha);
void sr_stroke_rect(sr_canvas *c, float x, float y, float w, float h,
                    float line, uint32_t rgb, float alpha);
void sr_fill_circle(sr_canvas *c, float cx, float cy, float r,
                    uint32_t rgb, float alpha);
void sr_fill_ellipse(sr_canvas *c, float cx, float cy, float rx, float ry,
                     uint32_t rgb, float alpha);
void sr_ring(sr_canvas *c, float cx, float cy, float r, float width,
             uint32_t rgb, float alpha);
void sr_line(sr_canvas *c, float x0, float y0, float x1, float y1,
             float width, uint32_t rgb, float alpha,
             int dash_on, int dash_off);
void sr_fill_triangle(sr_canvas *c, float x0, float y0, float x1, float y1,
                      float x2, float y2, uint32_t rgb, float alpha);
void sr_fill_convex(sr_canvas *c, const float *xs, const float *ys,
                    size_t count, uint32_t rgb, float alpha);

/*
 * Arbitrary polygon fill, concave permitted.
 *
 * sr_fill_convex() keeps pixels lying on the same side of every edge,
 * which is an inside test only while the polygon is convex.  Given a
 * concave outline it draws the intersection of the edges' half-planes,
 * which is a *smaller* shape than asked for, not a larger one: an L
 * renders as the block where its two arms overlap and both arms vanish.
 *
 * This walks scanlines and fills between pairs of edge crossings instead,
 * so any simple polygon works -- a zone routed around an obstacle, a
 * boundary following a fence line.
 *
 * Filling is even-odd, which has two consequences worth knowing:
 *
 * - Winding direction does not matter, matching sr_fill_triangle() and
 *   sr_fill_convex().  Hand-authored coordinates need not be ordered.
 * - A self-intersecting outline leaves the doubly-enclosed region empty
 *   rather than filled.  A five-point star drawn as one crossing loop is
 *   hollow in the middle.
 *
 * Spans are half-open: a pixel whose center falls exactly on a left or
 * top edge is filled, one on a right or bottom edge is not.  Two polygons
 * sharing an edge therefore tile it exactly once, with no seam and no
 * doubled blend where alpha is below 1.  sr_fill_convex() instead treats
 * every boundary as closed, so the two can disagree by a pixel wherever a
 * pixel center lands exactly on an edge; they agree everywhere else.
 *
 * Cost is proportional to rows times edges rather than to area times
 * edges, so this is also the faster of the two on any polygon large
 * enough to matter.
 */
void sr_fill_polygon(sr_canvas *c, const float *xs, const float *ys,
                     size_t count, uint32_t rgb, float alpha);

/*
 * Stroked polylines
 * -----------------
 * sr_line() strokes one segment.  Stroking a chain of them by calling it
 * once per segment is wrong in two measurable ways, both of which show up
 * in any graph or chart drawing:
 *
 * - Each call blends independently, so the round cap each segment puts at a
 *   shared vertex is blended twice.  At alpha 0.5 a plain segment pixel
 *   lands on 127 and the joint lands on 191 -- every bend grows a dark bead.
 * - The dash pattern is measured from the start of each segment, so the
 *   phase restarts at every vertex and the pattern breaks at every bend.
 *
 * sr_polyline() strokes the whole chain as one shape.  Coverage is the
 * maximum over the segments rather than a sequence of blends, so every
 * pixel is blended exactly once and interior vertices become round joins;
 * the dash phase is measured along the whole path, plus dash_offset.
 * Passing two points with SR_CAP_ROUND and no dash draws what sr_line()
 * draws.
 *
 * Joins are always round.  Caps apply only to the two free ends: SR_CAP_BUTT
 * ends the stroke on the end point (what you want when an arrowhead covers
 * the end), SR_CAP_SQUARE extends it by half the width, SR_CAP_ROUND is a
 * half disc.  A closed outline is drawn by repeating the first point last,
 * which makes both ends interior and the cap irrelevant.
 *
 * count must be at least 2; non-finite coordinates make the call a no-op.
 * Memory is one float per pixel of the clipped bounding box width, taken
 * from the stack for canvases up to 4096 pixels wide, plus one float per
 * point for paths longer than 128 points.
 */
typedef enum sr_cap {
    SR_CAP_ROUND = 0,
    SR_CAP_BUTT,
    SR_CAP_SQUARE
} sr_cap;

void sr_polyline(sr_canvas *c, const float *xs, const float *ys, size_t count,
                 float width, uint32_t rgb, float alpha,
                 int dash_on, int dash_off, float dash_offset, sr_cap cap);

/*
 * Anti-aliased polygon fill, concave permitted, even-odd like
 * sr_fill_polygon().
 *
 * sr_fill_polygon() and sr_fill_triangle() sample the pixel center, so their
 * coverage is 0 or 255 and nothing between: measured across a scanline of a
 * filled triangle, the only two values present are 0 and 255.  Beside an
 * sr_fill_circle(), whose rim carries the values in between, the difference
 * reads as a defect rather than a style -- which is exactly the pairing an
 * arrowhead on an edge into a round node makes.
 *
 * This samples four sub-scanlines per pixel row and computes exact
 * horizontal span overlap within each, so an edge at any angle carries
 * fractional coverage.  Cost is about four times sr_fill_polygon()'s.
 * Geometry rules are otherwise identical, including even-odd filling and
 * half-open spans, so the two agree on which pixels are fully inside.
 */
void sr_fill_polygon_aa(sr_canvas *c, const float *xs, const float *ys,
                        size_t count, uint32_t rgb, float alpha);

/*
 * Rounded rectangles: the default node shape of every modern diagram, and
 * the one shape that cannot be assembled from the existing primitives
 * without seams where the bars meet the corner arcs.
 *
 * Coverage comes from the exact signed distance to the rounded rectangle,
 * so both edges are anti-aliased and a stroke is a band around that
 * distance.  r is clamped to half the smaller side; r <= 0 draws square
 * corners and agrees with sr_fill_rect()/sr_stroke_rect() to within the
 * usual half-pixel coverage rule.  The stroke is centered on the outline,
 * like sr_ring() and unlike sr_stroke_rect(), whose bars sit inside it.
 */
void sr_fill_round_rect(sr_canvas *c, float x, float y, float w, float h,
                        float r, uint32_t rgb, float alpha);
void sr_stroke_round_rect(sr_canvas *c, float x, float y, float w, float h,
                          float r, float line, uint32_t rgb, float alpha);

/*
 * Flattens a cubic Bezier into a polyline for sr_polyline().  Curves are the
 * shape a routed graph edge wants and the shape sr_line() cannot make.
 *
 * Subdivision is adaptive: a span is split while its control points sit
 * further than tolerance from the chord, so a nearly straight curve costs
 * two points and a tight one costs as many as it needs.  tolerance is in
 * pixels and is clamped to at least 1/32.
 *
 * Returns the number of points the flattened curve needs, including both
 * end points, whether or not they were written.  Call it with capacity 0
 * (xs and ys may be NULL) to size a buffer, or pass a buffer and compare
 * the result against its capacity: a result larger than capacity means the
 * curve was truncated at the last point that fit.  Non-finite input returns
 * 0.  The point count is bounded by 2^SR_CUBIC_MAX_DEPTH + 1.
 */
#define SR_CUBIC_MAX_DEPTH 10

size_t sr_flatten_cubic(float x0, float y0, float x1, float y1,
                        float x2, float y2, float x3, float y3,
                        float tolerance, float *xs, float *ys, size_t capacity);

/*

 * Text over the embedded 8x16 font (ASCII 32..126; anything else renders
 * as '?').  scale is an integer pixel multiplier and is clamped to >= 1.
 * sr_text_width() returns the advance width of the string in pixels,
 * saturating at INT_MAX when it cannot be represented.
 * sr_text_outlined() draws a 1px black outline; sr_text_shadow() draws a
 * black drop shadow offset by one scaled pixel at 75% of alpha.
 */
int  sr_text_width(const char *s, int scale);
const uint8_t *sr_font_glyph(unsigned char ch);

/*
 * Selectable faces.  SR_FONT_FIXED_8X16 is what the calls above have always
 * drawn and stays the default, so existing callers are unaffected.
 * SR_FONT_COMPACT_7X14 is a narrower authored face at the same 8px advance:
 * the same string occupies the same width in either, only the glyphs and the
 * cell height differ.  A face is chosen per call rather than set globally,
 * because a global would make what a string looks like depend on what drew
 * before it.
 */
typedef enum sr_font_id {
    SR_FONT_FIXED_8X16 = 0,
    SR_FONT_COMPACT_7X14,
    SR_FONT_COUNT
} sr_font_id;

/* Advance per character and cell height, in unscaled pixels.  Both return 0
 * for an unknown face, which is also what its text draws. */
int sr_font_advance(sr_font_id font);
int sr_font_height(sr_font_id font);
/* The scanline rows of one glyph, sr_font_height() of them, MSB leftmost.
 * NULL for an unknown face; unmapped characters render as '?'. */
const uint8_t *sr_font_glyph_in(sr_font_id font, unsigned char ch);

int  sr_text_width_in(sr_font_id font, const char *s, int scale);
void sr_text_in(sr_font_id font, sr_canvas *c, float x, float y,
                const char *s, uint32_t rgb, float alpha, int scale);
void sr_text_center_in(sr_font_id font, sr_canvas *c, float cx, float y,
                       const char *s, uint32_t rgb, float alpha, int scale);
void sr_text(sr_canvas *c, float x, float y, const char *s,
             uint32_t rgb, float alpha, int scale);
void sr_text_center(sr_canvas *c, float cx, float y, const char *s,
                    uint32_t rgb, float alpha, int scale);
void sr_text_outlined(sr_canvas *c, float x, float y, const char *s,
                      uint32_t rgb, float alpha, int scale);
void sr_text_shadow(sr_canvas *c, float x, float y, const char *s,
                    uint32_t rgb, float alpha, int scale);

/*
 * Blits.  (x, y) is the destination of the source's top-left corner; every
 * blit clips against the destination bounds.
 *
 * - sr_blit: verbatim pixel copy, alpha byte included; source coverage is
 *   ignored.
 * - sr_blit_alpha: composites the source over the destination using each
 *   source pixel's alpha byte multiplied by the uniform alpha in [0,1].
 *   Source RGB is expected premultiplied by its alpha byte, which is what
 *   drawing into a transparent canvas produces; opaque pixels are plain
 *   0xFFRRGGBB.
 * - sr_blit_tint: like sr_blit_alpha but replaces the source color with
 *   rgb, using the source alpha purely as a mask.
 * - sr_blit_scaled: nearest-neighbor resample of the whole source into the
 *   w*h destination rectangle (source x = dst x * src_w / w), composited
 *   like sr_blit_alpha.
 * - sr_blit_transformed: composites the whole source after applying any
 *   combination of SR_TRANSFORM_FLIP_* bits.  Diagonal exchange is applied
 *   first and swaps the output dimensions.  tint_enabled selects either
 *   normal premultiplied-source compositing or source-alpha masking with rgb.
 *   Unknown transform bits make the call a no-op.
 * - sr_scale_canvas: scales the whole source onto the destination with
 *   nearest-neighbor sampling, preserving aspect ratio, centered, with
 *   opaque black letterbox bars; output alpha is forced opaque.
 *
 * Source and destination storage must not overlap for scaled, transformed,
 * or letterbox blits; passing the same pixel storage as both makes these
 * calls a no-op. The three unscaled blits support overlap within the same
 * canvas.
 */
void sr_blit(sr_canvas *dst, const sr_canvas *src, int x, int y);
void sr_blit_alpha(sr_canvas *dst, const sr_canvas *src, int x, int y,
                   float alpha);
void sr_blit_tint(sr_canvas *dst, const sr_canvas *src, int x, int y,
                  uint32_t rgb, float alpha);
void sr_blit_scaled(sr_canvas *dst, const sr_canvas *src, int x, int y,
                    int w, int h, float alpha);
void sr_blit_transformed(sr_canvas *dst, const sr_canvas *src, int x, int y,
                         uint8_t transform, float alpha, bool tint_enabled,
                         uint32_t rgb);
void sr_scale_canvas(sr_canvas *dst, const sr_canvas *src);

/* Loads a binary P6 PPM into a newly allocated canvas.  Comments and arbitrary
 * header whitespace are accepted; maxval must be 255.  *c must be empty or
 * uninitialized, is reset on entry, and owns its pixels on success. Failures
 * set errno: EINVAL for malformed/truncated input, EOVERFLOW for unsupported
 * dimensions, or the allocation/filesystem error. */
bool sr_load_ppm(sr_canvas *c, const char *path);

/* Writes the canvas as a binary P6 PPM (alpha dropped).  Returns false and
 * sets errno on an empty canvas, invalid path, or any I/O failure. */
bool sr_write_ppm(const sr_canvas *c, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SOFT_RASTER_H */
