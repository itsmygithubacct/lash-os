/*
 * soft-raster: anti-aliased software rasterization into 0xAARRGGBB pixels.
 *
 * The blending and coverage math is kept identical to the renderer these
 * routines were extracted from: alpha is quantized to 1/256 steps and each
 * channel moves toward the target color with an arithmetic-shift lerp, so a
 * frame drawn through this library matches the original games byte for byte
 * on an opaque canvas.
 */
#include "soft_raster.h"
#include "font8x16.h"
#include "font7x14.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static float clampf(float v, float lo, float hi)
{
    if (!(v >= lo)) return lo;
    return v > hi ? hi : v;
}

static bool dimensions_ok(int w, int h, size_t *pixel_count)
{
    size_t pixels;

    if (w <= 0 || h <= 0 || (size_t)w > SIZE_MAX / (size_t)h)
        return false;
    pixels = (size_t)w * (size_t)h;
    if (pixels > (size_t)INT_MAX ||
        pixels > SIZE_MAX / sizeof(uint32_t)) return false;
    if (pixel_count != NULL) *pixel_count = pixels;
    return true;
}

static bool canvas_ok(const sr_canvas *c)
{
    return c != NULL && c->px != NULL &&
           dimensions_ok(c->w, c->h, NULL);
}

static void reset_clip(sr_canvas *c)
{
    c->clip_x0 = 0;
    c->clip_y0 = 0;
    c->clip_x1 = c->w;
    c->clip_y1 = c->h;
}

/* ---------------------------------------------------------------- canvas */

bool sr_canvas_init(sr_canvas *c, int w, int h)
{
    size_t pixels;
    uint32_t *px;

    if (c == NULL) return false;
    *c = (sr_canvas){0};
    if (!dimensions_ok(w, h, &pixels)) return false;
    px = calloc(pixels, sizeof(uint32_t));
    if (px == NULL) return false;
    c->px = px;
    c->w = w;
    c->h = h;
    c->owns_px = true;
    reset_clip(c);
    return true;
}

void sr_canvas_wrap(sr_canvas *c, uint32_t *mem, int w, int h)
{
    if (c == NULL) return;
    *c = (sr_canvas){0};
    if (mem == NULL || !dimensions_ok(w, h, NULL)) return;
    c->px = mem;
    c->w = w;
    c->h = h;
    c->owns_px = false;
    reset_clip(c);
}

void sr_canvas_free(sr_canvas *c)
{
    if (c == NULL) return;
    if (c->owns_px) free(c->px);
    *c = (sr_canvas){0};
}

void sr_canvas_set_clip(sr_canvas *c, int x, int y, int w, int h)
{
    if (c == NULL) return;
    int64_t right = (int64_t)x + w;
    int64_t bottom = (int64_t)y + h;
    c->clip_x0 = x < 0 ? 0 : x > c->w ? c->w : x;
    c->clip_y0 = y < 0 ? 0 : y > c->h ? c->h : y;
    c->clip_x1 = right < 0 ? 0 : right > c->w ? c->w : (int)right;
    c->clip_y1 = bottom < 0 ? 0 : bottom > c->h ? c->h : (int)bottom;
    if (w <= 0 || c->clip_x1 < c->clip_x0) c->clip_x1 = c->clip_x0;
    if (h <= 0 || c->clip_y1 < c->clip_y0) c->clip_y1 = c->clip_y0;
}

void sr_canvas_reset_clip(sr_canvas *c)
{
    if (c != NULL) reset_clip(c);
}

bool sr_pack_rgba(const sr_canvas *c, uint8_t *rgba, size_t byte_count)
{
    size_t pixels;

    if (!canvas_ok(c) || rgba == NULL ||
        !dimensions_ok(c->w, c->h, &pixels)) return false;
    if (pixels > SIZE_MAX / 4u || byte_count < pixels * 4u) return false;
    for (size_t i = 0u; i < pixels; i++) {
        uint32_t pixel = c->px[i];
        rgba[i * 4u] = (uint8_t)(pixel >> 16);
        rgba[i * 4u + 1u] = (uint8_t)(pixel >> 8);
        rgba[i * 4u + 2u] = (uint8_t)pixel;
        rgba[i * 4u + 3u] = (uint8_t)(pixel >> 24);
    }
    return true;
}

static void pack_rgb_pixels(const uint32_t *pixels, uint8_t *rgb,
                            size_t pixel_count)
{
    for (size_t i = 0u; i < pixel_count; ++i) {
        const uint32_t pixel = pixels[i];
        rgb[i * 3u] = (uint8_t)(pixel >> 16);
        rgb[i * 3u + 1u] = (uint8_t)(pixel >> 8);
        rgb[i * 3u + 2u] = (uint8_t)pixel;
    }
}

bool sr_pack_rgb(const sr_canvas *c, uint8_t *rgb, size_t byte_count)
{
    size_t pixels;

    if (!canvas_ok(c) || rgb == NULL ||
        !dimensions_ok(c->w, c->h, &pixels)) return false;
    if (pixels > SIZE_MAX / 3u || byte_count < pixels * 3u) return false;
    pack_rgb_pixels(c->px, rgb, pixels);
    return true;
}

/* ---------------------------------------------------------------- colors */

uint32_t sr_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

uint32_t sr_mix(uint32_t a, uint32_t b, float t)
{
    t = clampf(t, 0.0f, 1.0f);
    int ar = (int)((a >> 16) & 255u), ag = (int)((a >> 8) & 255u);
    int ab = (int)(a & 255u);
    int br = (int)((b >> 16) & 255u), bg = (int)((b >> 8) & 255u);
    int bb = (int)(b & 255u);
    int r = ar + (int)((float)(br - ar) * t);
    int g = ag + (int)((float)(bg - ag) * t);
    int bl = ab + (int)((float)(bb - ab) * t);
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)bl;
}

uint32_t sr_scale_rgb(uint32_t rgb, float k)
{
    k = clampf(k, 0.0f, 2.0f);
    int r = (int)((float)((rgb >> 16) & 255u) * k);
    int g = (int)((float)((rgb >> 8) & 255u) * k);
    int b = (int)((float)(rgb & 255u) * k);
    if (r > 255) r = 255;
    if (g > 255) g = 255;
    if (b > 255) b = 255;
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

/* ---------------------------------------------------------------- pixels */

void sr_clear(sr_canvas *c, uint32_t rgb)
{
    size_t i = 0u;

    if (!canvas_ok(c)) return;
    uint32_t value = 0xff000000u | (rgb & 0x00ffffffu);
    size_t n = (size_t)c->w * (size_t)c->h;
    for (; i + 8u <= n; i += 8u) {
        c->px[i] = value;
        c->px[i + 1u] = value;
        c->px[i + 2u] = value;
        c->px[i + 3u] = value;
        c->px[i + 4u] = value;
        c->px[i + 5u] = value;
        c->px[i + 6u] = value;
        c->px[i + 7u] = value;
    }
    for (; i < n; ++i)
        c->px[i] = value;
}

void sr_px(sr_canvas *c, int x, int y, uint32_t rgb)
{
    if (!canvas_ok(c) || x < c->clip_x0 || x >= c->clip_x1 ||
        y < c->clip_y0 || y >= c->clip_y1) return;
    c->px[(size_t)y * (size_t)c->w + (size_t)x] =
        0xff000000u | (rgb & 0x00ffffffu);
}

/* Core blend, shared by every primitive.  ai is coverage in [0,256]; the
 * RGB channels lerp toward the color and the alpha byte lerps toward 255
 * with the same arithmetic-shift fixed-point step the games use.  At
 * ai == 256 every channel lands exactly on the color and the alpha byte
 * on 255, so a fully covered opaque pixel equals a plain store. */
static void blend_px_ai(sr_canvas *c, int x, int y, uint32_t rgb, int ai)
{
    uint32_t *p = &c->px[(size_t)y * (size_t)c->w + (size_t)x];
    uint32_t d = *p;
    int dr = (int)((d >> 16) & 255u);
    int dg = (int)((d >> 8) & 255u);
    int db = (int)(d & 255u);
    int da = (int)(d >> 24);
    int r = (int)((rgb >> 16) & 255u);
    int g = (int)((rgb >> 8) & 255u);
    int b = (int)(rgb & 255u);
    dr += ((r - dr) * ai) >> 8;
    dg += ((g - dg) * ai) >> 8;
    db += ((b - db) * ai) >> 8;
    da += ((255 - da) * ai) >> 8;
    *p = ((uint32_t)da << 24) | ((uint32_t)dr << 16) |
         ((uint32_t)dg << 8) | (uint32_t)db;
}

static int coverage_ai(float a)
{
    return a >= 1.0f ? 256 : (int)(a * 256.0f + 0.5f);
}

static void blend_px_unchecked(sr_canvas *c, int x, int y, uint32_t rgb,
                               float a)
{
    int ai;

    if (!(a > 0.0f)) return;
    ai = coverage_ai(a);
    if (ai <= 0) return;
    blend_px_ai(c, x, y, rgb, ai);
}

static void blend_px(sr_canvas *c, int x, int y, uint32_t rgb, float a)
{
    if (x < c->clip_x0 || x >= c->clip_x1 ||
        y < c->clip_y0 || y >= c->clip_y1) return;
    blend_px_unchecked(c, x, y, rgb, a);
}

void sr_blend(sr_canvas *c, int x, int y, uint32_t rgb, float alpha)
{
    if (!canvas_ok(c)) return;
    blend_px(c, x, y, rgb, alpha);
}

/* Clip a floating-point coordinate range to the active canvas clip and
 * convert it to ints.  This keeps loops bounded and casts representable. */
static int clip_lo(double v, int lower, int upper)
{
    const double rounded = floor(v);

    if (isnan(v) || rounded <= (double)lower) return lower;
    if (rounded >= (double)upper) return upper;
    return (int)rounded;
}

static int clip_hi(double v, int lower, int upper)
{
    const double rounded = ceil(v);

    if (isnan(v) || rounded <= (double)lower) return lower;
    if (rounded >= (double)upper) return upper;
    return (int)rounded;
}

/* ------------------------------------------------------------ primitives */

/* Fractional-coverage span of sr_fill_rect: the exact per-pixel formula. */
static void fill_rect_span(sr_canvas *c, int px0, int px1, int py,
                           float x, float xe, uint32_t rgb,
                           float alpha, float cy)
{
    for (int px = px0; px < px1; px++) {
        float cx = fminf((float)(px + 1), xe) - fmaxf((float)px, x);
        if (cx <= 0.0f) continue;
        if (cx > 1.0f) cx = 1.0f;
        blend_px_unchecked(c, px, py, rgb, alpha * cx * cy);
    }
}

/* Fully covered span: cx and cy are exactly 1.0f, so the blend collapses
 * to uniform alpha and, at alpha >= 1, to a plain opaque store. */
static void fill_interior_span(sr_canvas *c, int px0, int px1, int py,
                               uint32_t rgb, float alpha)
{
    if (px0 >= px1) return;
    if (alpha >= 1.0f) {
        const uint32_t value = 0xff000000u | (rgb & 0x00ffffffu);
        uint32_t *row = &c->px[(size_t)py * (size_t)c->w];

        for (int px = px0; px < px1; px++)
            row[px] = value;
        return;
    }
    {
        const int ai = coverage_ai(alpha);

        if (ai <= 0) return;
        for (int px = px0; px < px1; px++)
            blend_px_ai(c, px, py, rgb, ai);
    }
}

void sr_fill_rect(sr_canvas *c, float x, float y, float w, float h,
                  uint32_t rgb, float alpha)
{
    int x0;
    int x1;
    int y0;
    int y1;
    int ix0;
    int ix1;
    int iy0;
    int iy1;

    if (!canvas_ok(c) || !isfinite(x) || !isfinite(y) ||
        !isfinite(w) || !isfinite(h) || w <= 0.0f || h <= 0.0f ||
        !(alpha > 0.0f)) return;
    x0 = clip_lo(x, c->clip_x0, c->clip_x1);
    x1 = clip_hi(x + w, c->clip_x0, c->clip_x1);
    y0 = clip_lo(y, c->clip_y0, c->clip_y1);
    y1 = clip_hi(y + h, c->clip_y0, c->clip_y1);
    /* Interior pixels -- columns and rows the rectangle covers end to
     * end -- see min(px + 1, x + w) - max(px, x) collapse to exactly
     * 1.0f, so they take the uniform-alpha span above while the
     * fractional edge strips keep the exact per-pixel formula.  The 2^24
     * cap keeps the (float) casts of pixel coordinates exact. */
    ix0 = clip_hi((double)x, x0, x1);
    ix1 = clip_lo((double)(x + w), x0, x1);
    iy0 = clip_hi((double)y, y0, y1);
    iy1 = clip_lo((double)(y + h), y0, y1);
    if (ix1 > (1 << 24)) ix1 = 1 << 24;
    if (iy1 > (1 << 24)) iy1 = 1 << 24;
    if (ix0 > ix1) ix0 = ix1;
    if (iy0 > iy1) iy0 = iy1;
    for (int py = y0; py < y1; py++) {
        float cy = fminf((float)(py + 1), y + h) - fmaxf((float)py, y);
        if (cy <= 0.0f) continue;
        if (cy > 1.0f) cy = 1.0f;
        if (py >= iy0 && py < iy1 && ix0 < ix1) {
            fill_rect_span(c, x0, ix0, py, x, x + w, rgb, alpha, cy);
            fill_interior_span(c, ix0, ix1, py, rgb, alpha);
            fill_rect_span(c, ix1, x1, py, x, x + w, rgb, alpha, cy);
        } else {
            fill_rect_span(c, x0, x1, py, x, x + w, rgb, alpha, cy);
        }
    }
}

void sr_stroke_rect(sr_canvas *c, float x, float y, float w, float h,
                    float line, uint32_t rgb, float alpha)
{
    if (!isfinite(x) || !isfinite(y) || !isfinite(w) || !isfinite(h) ||
        !isfinite(line) || line <= 0.0f) return;
    sr_fill_rect(c, x, y, w, line, rgb, alpha);
    sr_fill_rect(c, x, y + h - line, w, line, rgb, alpha);
    sr_fill_rect(c, x, y, line, h, rgb, alpha);
    sr_fill_rect(c, x + w - line, y, line, h, rgb, alpha);
}

void sr_fill_circle(sr_canvas *c, float cx, float cy, float r,
                    uint32_t rgb, float alpha)
{
    int y0;
    int y1;

    if (!canvas_ok(c) || !isfinite(cx) || !isfinite(cy) ||
        !isfinite(r) || r <= 0.0f || !(alpha > 0.0f)) return;
    float r_out = r + 0.5f, r_in = r - 0.5f;
    float r_out2 = r_out * r_out;
    float r_in2 = r_in > 0.0f ? r_in * r_in : 0.0f;
    y0 = clip_lo(cy - r_out, c->clip_y0, c->clip_y1);
    y1 = clip_hi(cy + r_out, c->clip_y0, c->clip_y1) - 1;
    for (int y = y0; y <= y1; y++) {
        float dy = (float)y + 0.5f - cy;
        float w2 = r_out2 - dy * dy;
        if (w2 <= 0.0f) continue;
        float half = sqrtf(w2);
        int x0 = clip_lo(cx - half, c->clip_x0, c->clip_x1);
        int x1 = clip_hi(cx + half, c->clip_x0, c->clip_x1) - 1;
        for (int x = x0; x <= x1; x++) {
            float dx = (float)x + 0.5f - cx;
            float d2 = dx * dx + dy * dy;
            if (d2 >= r_out2) continue;
            if (d2 <= r_in2) {
                blend_px_unchecked(c, x, y, rgb, alpha);
            } else {
                float cov = r_out - sqrtf(d2);
                blend_px_unchecked(c, x, y, rgb,
                                   alpha * (cov > 1.0f ? 1.0f : cov));
            }
        }
    }
}

void sr_fill_ellipse(sr_canvas *c, float cx, float cy, float rx, float ry,
                     uint32_t rgb, float alpha)
{
    int x0;
    int x1;
    int y0;
    int y1;

    if (!canvas_ok(c) || !isfinite(cx) || !isfinite(cy) ||
        !isfinite(rx) || !isfinite(ry) || rx <= 0.0f || ry <= 0.0f ||
        !(alpha > 0.0f)) return;
    x0 = clip_lo(cx - rx - 1.0f, c->clip_x0, c->clip_x1);
    x1 = clip_hi(cx + rx + 1.0f, c->clip_x0, c->clip_x1);
    y0 = clip_lo(cy - ry - 1.0f, c->clip_y0, c->clip_y1);
    y1 = clip_hi(cy + ry + 1.0f, c->clip_y0, c->clip_y1);
    float edge_scale = fminf(rx, ry);
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            float dx = ((float)x + 0.5f - cx) / rx;
            float dy = ((float)y + 0.5f - cy) / ry;
            float coverage = (1.0f - sqrtf(dx * dx + dy * dy)) * edge_scale
                           + 0.5f;
            if (coverage <= 0.0f) continue;
            blend_px_unchecked(c, x, y, rgb,
                               alpha * fminf(coverage, 1.0f));
        }
    }
}

/* One x-run of sr_ring's annulus: the exact per-pixel coverage test. */
static void ring_span(sr_canvas *c, int rx0, int rx1, int y, float cx,
                      float cy, float r, float hw, uint32_t rgb,
                      float alpha)
{
    for (int x = rx0; x < rx1; x++) {
        float dx = (float)x + 0.5f - cx;
        float dy = (float)y + 0.5f - cy;
        float d = sqrtf(dx * dx + dy * dy);
        float cov = hw + 0.5f - fabsf(d - r);
        if (cov <= 0.0f) continue;
        blend_px_unchecked(c, x, y, rgb,
                           alpha * (cov > 1.0f ? 1.0f : cov));
    }
}

void sr_ring(sr_canvas *c, float cx, float cy, float r, float width,
             uint32_t rgb, float alpha)
{
    int x0;
    int x1;
    int y0;
    int y1;

    if (!canvas_ok(c) || !isfinite(cx) || !isfinite(cy) ||
        !isfinite(r) || !isfinite(width) || r <= 0.0f || width <= 0.0f ||
        !(alpha > 0.0f)) return;
    float hw = width * 0.5f;
    x0 = clip_lo(cx - r - hw - 1.0f, c->clip_x0, c->clip_x1);
    x1 = clip_hi(cx + r + hw + 1.0f, c->clip_x0, c->clip_x1);
    y0 = clip_lo(cy - r - hw - 1.0f, c->clip_y0, c->clip_y1);
    y1 = clip_hi(cy + r + hw + 1.0f, c->clip_y0, c->clip_y1);
    /* Pixels can pass the coverage test only within the outer radius and
     * never deep inside the hole, so each row shrinks to two runs: the
     * outer chord minus the inner chord.  Both chords are computed in
     * double against radii padded (outer) or shrunk (inner) by a whole
     * pixel of distance, so every pixel the float coverage test could
     * accept stays inside the runs; extreme coordinates, where rounding
     * could outgrow that slack, keep the full bounding-box row. */
    const bool narrow = fabsf(cx) <= 65536.0f && fabsf(cy) <= 65536.0f &&
                        r + hw <= 65536.0f;
    const double pad_out = (double)r + (double)hw + 1.5;
    const double out2 = pad_out * pad_out;
    const double pad_in = (double)r - (double)hw - 1.5;
    const double in2 = pad_in > 0.0 ? pad_in * pad_in : 0.0;
    for (int y = y0; y < y1; y++) {
        int rx0 = x0;
        int rx1 = x1;
        int hx0;
        int hx1;

        if (narrow) {
            const double dy_row = (double)y + 0.5 - (double)cy;
            const double dy2 = dy_row * dy_row;

            if (dy2 >= out2) continue;
            {
                const double half_out = sqrt(out2 - dy2);
                rx0 = clip_lo((double)cx - half_out - 1.0, x0, x1);
                rx1 = clip_hi((double)cx + half_out + 1.0, x0, x1);
            }
            hx0 = rx1;
            hx1 = rx1;
            if (dy2 < in2) {
                const double half_in = sqrt(in2 - dy2);

                hx0 = clip_hi((double)cx - half_in + 0.5, rx0, rx1);
                hx1 = clip_lo((double)cx + half_in - 0.5, rx0, rx1);
                if (hx1 < hx0) {
                    hx0 = rx1;
                    hx1 = rx1;
                }
            }
        } else {
            hx0 = rx1;
            hx1 = rx1;
        }
        ring_span(c, rx0, hx0, y, cx, cy, r, hw, rgb, alpha);
        ring_span(c, hx1, rx1, y, cx, cy, r, hw, rgb, alpha);
    }
}

void sr_line(sr_canvas *c, float x0, float y0, float x1, float y1,
             float width, uint32_t rgb, float alpha,
             int dash_on, int dash_off)
{
    if (!canvas_ok(c) || !isfinite(x0) || !isfinite(y0) ||
        !isfinite(x1) || !isfinite(y1) || !isfinite(width) ||
        !(alpha > 0.0f)) return;
    float dx = x1 - x0, dy = y1 - y0;
    float len2 = dx * dx + dy * dy;
    float hw = width * 0.5f;
    if (hw < 0.5f) hw = 0.5f;
    if (len2 < 0.25f) {
        sr_fill_circle(c, x0, y0, hw, rgb, alpha);
        return;
    }
    float len = sqrtf(len2);
    int x_min = clip_lo(fminf(x0, x1) - hw - 1.0f,
                        c->clip_x0, c->clip_x1);
    int x_max = clip_hi(fmaxf(x0, x1) + hw + 1.0f,
                        c->clip_x0, c->clip_x1);
    int y_min = clip_lo(fminf(y0, y1) - hw - 1.0f,
                        c->clip_y0, c->clip_y1);
    int y_max = clip_hi(fmaxf(y0, y1) + hw + 1.0f,
                        c->clip_y0, c->clip_y1);
    int64_t period = (int64_t)dash_on + (int64_t)dash_off;
    /* Pixels can only pass the coverage test inside the slab where the
     * perpendicular distance to the infinite line reaches hw + 0.5, so for
     * non-horizontal segments each row's x range shrinks from the full
     * bounding box to the capsule's width.  The interval is computed in
     * double and widened by a quarter pixel of distance slack plus a whole
     * pixel per side, keeping every pixel the float coverage test could
     * accept inside it; extreme coordinates, where rounding could outgrow
     * that slack, fall back to the full bounding-box row. */
    const bool narrow = dy != 0.0f &&
        fabsf(x0) <= 65536.0f && fabsf(y0) <= 65536.0f &&
        fabsf(x1) <= 65536.0f && fabsf(y1) <= 65536.0f;
    const double span_half = narrow
        ? ((double)hw + 0.75) * (double)len / fabs((double)dy) + 1.0
        : 0.0;
    for (int y = y_min; y < y_max; y++) {
        int row_x0 = x_min;
        int row_x1 = x_max;
        if (narrow) {
            const double center = (double)x0 + (double)dx *
                ((double)y + 0.5 - (double)y0) / (double)dy;
            row_x0 = clip_lo(center - span_half - 1.0, x_min, x_max);
            row_x1 = clip_hi(center + span_half + 1.0, x_min, x_max);
        }
        for (int x = row_x0; x < row_x1; x++) {
            float px = (float)x + 0.5f - x0;
            float py = (float)y + 0.5f - y0;
            float t = clampf((px * dx + py * dy) / len2, 0.0f, 1.0f);
            float qx = px - t * dx;
            float qy = py - t * dy;
            float cov = hw + 0.5f - sqrtf(qx * qx + qy * qy);
            if (cov <= 0.0f) continue;
            if (cov > 1.0f) cov = 1.0f;
            if (dash_on >= 0 && dash_off >= 0 && period > 0 &&
                fmodf(t * len, (float)period) >= (float)dash_on) continue;
            blend_px_unchecked(c, x, y, rgb, alpha * cov);
        }
    }
}

static float edge_fn(float ax, float ay, float bx, float by,
                     float px, float py)
{
    return (px - ax) * (by - ay) - (py - ay) * (bx - ax);
}

static double edge_fn_double(double ax, double ay, double bx, double by,
                             double px, double py)
{
    return (px - ax) * (by - ay) - (py - ay) * (bx - ax);
}

void sr_fill_triangle(sr_canvas *c, float x0, float y0, float x1, float y1,
                      float x2, float y2, uint32_t rgb, float alpha)
{
    int min_x;
    int max_x;
    int min_y;
    int max_y;
    float area;

    if (!canvas_ok(c) || !isfinite(x0) || !isfinite(y0) ||
        !isfinite(x1) || !isfinite(y1) || !isfinite(x2) || !isfinite(y2) ||
        !(alpha > 0.0f)) return;
    area = edge_fn(x0, y0, x1, y1, x2, y2);
    if (area == 0.0f ||
        (!isfinite(area) &&
         edge_fn_double(x0, y0, x1, y1, x2, y2) == 0.0)) return;
    min_x = clip_lo(fminf(x0, fminf(x1, x2)) - 1.0f,
                    c->clip_x0, c->clip_x1);
    max_x = clip_hi(fmaxf(x0, fmaxf(x1, x2)) + 1.0f,
                    c->clip_x0, c->clip_x1) - 1;
    min_y = clip_lo(fminf(y0, fminf(y1, y2)) - 1.0f,
                    c->clip_y0, c->clip_y1);
    max_y = clip_hi(fmaxf(y0, fmaxf(y1, y2)) + 1.0f,
                    c->clip_y0, c->clip_y1) - 1;
    const bool opaque = alpha >= 1.0f;
    const uint32_t opaque_value = 0xff000000u | (rgb & 0x00ffffffu);
    const int ai = coverage_ai(alpha);
    if (ai <= 0) return;
    for (int y = min_y; y <= max_y; y++) {
        for (int x = min_x; x <= max_x; x++) {
            float px = (float)x + 0.5f;
            float py = (float)y + 0.5f;
            float e0 = edge_fn(x0, y0, x1, y1, px, py);
            float e1 = edge_fn(x1, y1, x2, y2, px, py);
            float e2 = edge_fn(x2, y2, x0, y0, px, py);
            bool neg;
            bool pos;

            if (isfinite(e0) && isfinite(e1) && isfinite(e2)) {
                neg = e0 < 0.0f || e1 < 0.0f || e2 < 0.0f;
                pos = e0 > 0.0f || e1 > 0.0f || e2 > 0.0f;
            } else {
                const double de0 = edge_fn_double(x0, y0, x1, y1, px, py);
                const double de1 = edge_fn_double(x1, y1, x2, y2, px, py);
                const double de2 = edge_fn_double(x2, y2, x0, y0, px, py);

                neg = de0 < 0.0 || de1 < 0.0 || de2 < 0.0;
                pos = de0 > 0.0 || de1 > 0.0 || de2 > 0.0;
            }
            if (!(neg && pos)) {
                /* Uniform alpha: an opaque store, or the blend with its
                 * coverage conversion hoisted, is byte-identical. */
                if (opaque)
                    c->px[(size_t)y * (size_t)c->w + (size_t)x] =
                        opaque_value;
                else
                    blend_px_ai(c, x, y, rgb, ai);
            }
        }
    }
}

void sr_fill_convex(sr_canvas *c, const float *xs, const float *ys,
                    size_t count, uint32_t rgb, float alpha)
{
    if (!canvas_ok(c) || xs == NULL || ys == NULL || count < 3u ||
        !(alpha > 0.0f) || !isfinite(xs[0]) || !isfinite(ys[0])) return;
    float min_x = xs[0], max_x = xs[0], min_y = ys[0], max_y = ys[0];
    for (size_t i = 1u; i < count; i++) {
        if (!isfinite(xs[i]) || !isfinite(ys[i])) return;
        min_x = fminf(min_x, xs[i]);
        max_x = fmaxf(max_x, xs[i]);
        min_y = fminf(min_y, ys[i]);
        max_y = fmaxf(max_y, ys[i]);
    }
    int x0 = clip_lo(min_x, c->clip_x0, c->clip_x1);
    int x1 = clip_hi(max_x, c->clip_x0, c->clip_x1);
    int y0 = clip_lo(min_y, c->clip_y0, c->clip_y1);
    int y1 = clip_hi(max_y, c->clip_y0, c->clip_y1);
    const bool opaque = alpha >= 1.0f;
    const uint32_t opaque_value = 0xff000000u | (rgb & 0x00ffffffu);
    const int ai = coverage_ai(alpha);
    if (ai <= 0) return;
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            float px = (float)x + 0.5f, py = (float)y + 0.5f;
            bool negative = false, positive = false;
            for (size_t i = 0u; i < count; i++) {
                size_t next = i + 1u == count ? 0u : i + 1u;
                float edge = edge_fn(xs[i], ys[i], xs[next], ys[next], px, py);
                if (isfinite(edge)) {
                    negative = negative || edge < 0.0f;
                    positive = positive || edge > 0.0f;
                } else {
                    const double precise = edge_fn_double(
                        xs[i], ys[i], xs[next], ys[next], px, py);

                    negative = negative || precise < 0.0;
                    positive = positive || precise > 0.0;
                }
            }
            if (!(negative && positive)) {
                if (opaque)
                    c->px[(size_t)y * (size_t)c->w + (size_t)x] =
                        opaque_value;
                else
                    blend_px_ai(c, x, y, rgb, ai);
            }
        }
    }
}

/* Even-odd scanline fill.  Unlike sr_fill_convex() above, which asks
 * whether a pixel lies on one side of every edge, this counts how many
 * edges the scanline crosses to the pixel's left -- the only one of the
 * two that is an inside test for a concave outline.
 *
 * Crossings per scanline are bounded by the vertex count, so a stack
 * buffer covers every polygon anyone hand-authors and the heap is only
 * touched by generated outlines. */
#define POLY_STACK_CROSSINGS 64u

void sr_fill_polygon(sr_canvas *c, const float *xs, const float *ys,
                     size_t count, uint32_t rgb, float alpha)
{
    if (!canvas_ok(c) || xs == NULL || ys == NULL || count < 3u ||
        count > SIZE_MAX / sizeof(double) || !(alpha > 0.0f) ||
        !isfinite(xs[0]) || !isfinite(ys[0])) return;

    float min_y = ys[0], max_y = ys[0];
    for (size_t i = 1u; i < count; i++) {
        if (!isfinite(xs[i]) || !isfinite(ys[i])) return;
        min_y = fminf(min_y, ys[i]);
        max_y = fmaxf(max_y, ys[i]);
    }
    int y0 = clip_lo(min_y, c->clip_y0, c->clip_y1);
    int y1 = clip_hi(max_y, c->clip_y0, c->clip_y1);
    if (y0 >= y1) return;

    const bool opaque = alpha >= 1.0f;
    const uint32_t opaque_value = 0xff000000u | (rgb & 0x00ffffffu);
    const int ai = coverage_ai(alpha);
    if (ai <= 0) return;

    double stack_crossings[POLY_STACK_CROSSINGS];
    double *crossings = stack_crossings;
    if (count > POLY_STACK_CROSSINGS) {
        crossings = (double *)malloc(count * sizeof(double));
        if (crossings == NULL) return;
    }

    for (int y = y0; y < y1; y++) {
        float py = (float)y + 0.5f;
        size_t found = 0u;
        for (size_t i = 0u; i < count; i++) {
            size_t next = i + 1u == count ? 0u : i + 1u;
            float yi = ys[i], yj = ys[next];
            /* Half-open in y: an edge spans [min, max), so a vertex shared
             * by two edges is counted once and a horizontal edge not at
             * all.  Without this a scanline through a vertex fills the
             * wrong side of it. */
            if ((yi <= py) == (yj <= py)) continue;
            {
                const float crossing =
                    xs[i] + (py - yi) / (yj - yi) * (xs[next] - xs[i]);

                crossings[found++] = isfinite(crossing)
                    ? (double)crossing
                    : (double)xs[i] + ((double)py - (double)yi) /
                      ((double)yj - (double)yi) *
                      ((double)xs[next] - (double)xs[i]);
            }
        }
        if (found < 2u) continue;

        for (size_t a = 1u; a < found; a++) {   /* insertion sort: found is small */
            double v = crossings[a];
            size_t b = a;
            while (b > 0u && crossings[b - 1u] > v) {
                crossings[b] = crossings[b - 1u];
                b--;
            }
            crossings[b] = v;
        }

        for (size_t k = 0u; k + 1u < found; k += 2u) {
            /* Pixel x is inside when its center x + 0.5 falls in the span. */
            int sx = clip_hi(crossings[k] - 0.5,
                             c->clip_x0, c->clip_x1);
            int ex = clip_hi(crossings[k + 1u] - 0.5,
                             c->clip_x0, c->clip_x1);
            if (opaque) {
                uint32_t *row = &c->px[(size_t)y * (size_t)c->w];

                for (int x = sx; x < ex; x++)
                    row[x] = opaque_value;
            } else {
                for (int x = sx; x < ex; x++)
                    blend_px_ai(c, x, y, rgb, ai);
            }
        }
    }

    if (crossings != stack_crossings) free(crossings);
}

/* ------------------------------------------------ 0.5 graph primitives */

/*
 * Several of the routines below accumulate coverage for one scanline before
 * blending it, which is what lets a shape made of many overlapping pieces
 * blend each pixel exactly once.  One row of floats is all that needs to be
 * held, and a canvas up to SR_ROW_STACK_PIXELS wide holds it on the stack.
 */
#define SR_ROW_STACK_PIXELS 4096u
#define SR_POLYLINE_STACK_POINTS 128u
#define SR_AA_SUBSAMPLES 4

static float sat(float v)
{
    if (!(v > 0.0f)) return 0.0f;
    return v > 1.0f ? 1.0f : v;
}

/* Blend an accumulated coverage row into the canvas. */
static void blend_cov_row(sr_canvas *c, int y, int x0, int x1,
                          const float *row, uint32_t rgb, float alpha)
{
    for (int x = x0; x < x1; x++) {
        float cov = row[(size_t)(x - x0)];
        if (cov > 0.0f)
            blend_px_unchecked(c, x, y, rgb, alpha * sat(cov));
    }
}

/* Coverage of one stroked segment at a pixel center, with the cap rule for
 * each end.  cap_a/cap_b are sr_cap values; an interior vertex uses
 * SR_CAP_ROUND, which is what makes the join round. */
static float segment_coverage(float ax, float ay, float bx, float by,
                              float len, float hw, float px, float py,
                              int cap_a, int cap_b, float *along)
{
    float dx = bx - ax, dy = by - ay;
    float rx = px - ax, ry = py - ay;
    float u, perp;

    if (len > 0.0f) {
        u = (rx * dx + ry * dy) / len;
        perp = fabsf(rx * dy - ry * dx) / len;
    } else {
        u = 0.0f;
        perp = sqrtf(rx * rx + ry * ry);
    }
    if (along != NULL) *along = u < 0.0f ? 0.0f : (u > len ? len : u);

    float cov = sat(hw + 0.5f - perp);
    if (cov <= 0.0f) return 0.0f;

    switch (cap_a) {
    case SR_CAP_BUTT:   cov = fminf(cov, sat(u + 0.5f)); break;
    case SR_CAP_SQUARE: cov = fminf(cov, sat(u + hw + 0.5f)); break;
    default:
        if (u < 0.0f)
            cov = fminf(cov, sat(hw + 0.5f - sqrtf(rx * rx + ry * ry)));
        break;
    }
    if (cov <= 0.0f) return 0.0f;

    float v = len - u;
    switch (cap_b) {
    case SR_CAP_BUTT:   cov = fminf(cov, sat(v + 0.5f)); break;
    case SR_CAP_SQUARE: cov = fminf(cov, sat(v + hw + 0.5f)); break;
    default:
        if (v < 0.0f) {
            float qx = px - bx, qy = py - by;
            cov = fminf(cov, sat(hw + 0.5f - sqrtf(qx * qx + qy * qy)));
        }
        break;
    }
    return cov;
}

/* fmod that never returns a negative remainder, so a negative dash_offset
 * shifts the pattern instead of inverting it. */
static float dash_phase(float s, float period)
{
    float m = fmodf(s, period);
    return m < 0.0f ? m + period : m;
}

void sr_polyline(sr_canvas *c, const float *xs, const float *ys, size_t count,
                 float width, uint32_t rgb, float alpha,
                 int dash_on, int dash_off, float dash_offset, sr_cap cap)
{
    if (!canvas_ok(c) || xs == NULL || ys == NULL || count < 2u ||
        !isfinite(width) || !isfinite(dash_offset) || !(alpha > 0.0f))
        return;
    if (cap != SR_CAP_ROUND && cap != SR_CAP_BUTT && cap != SR_CAP_SQUARE)
        return;
    if (count > SIZE_MAX / sizeof(float)) return;

    float min_x = xs[0], max_x = xs[0], min_y = ys[0], max_y = ys[0];
    for (size_t i = 0u; i < count; i++) {
        if (!isfinite(xs[i]) || !isfinite(ys[i])) return;
        min_x = fminf(min_x, xs[i]);
        max_x = fmaxf(max_x, xs[i]);
        min_y = fminf(min_y, ys[i]);
        max_y = fmaxf(max_y, ys[i]);
    }

    float hw = width * 0.5f;
    if (hw < 0.5f) hw = 0.5f;
    float pad = hw + 1.0f;
    if (cap == SR_CAP_SQUARE) pad += hw;

    int bx0 = clip_lo((double)min_x - (double)pad, c->clip_x0, c->clip_x1);
    int bx1 = clip_hi((double)max_x + (double)pad, c->clip_x0, c->clip_x1);
    int by0 = clip_lo((double)min_y - (double)pad, c->clip_y0, c->clip_y1);
    int by1 = clip_hi((double)max_y + (double)pad, c->clip_y0, c->clip_y1);
    if (bx0 >= bx1 || by0 >= by1) return;

    float stack_cum[SR_POLYLINE_STACK_POINTS];
    float *cum = stack_cum;
    if (count > SR_POLYLINE_STACK_POINTS) {
        cum = (float *)malloc(count * sizeof(float));
        if (cum == NULL) return;
    }
    cum[0] = 0.0f;
    for (size_t i = 1u; i < count; i++) {
        float sx = xs[i] - xs[i - 1u], sy = ys[i] - ys[i - 1u];
        cum[i] = cum[i - 1u] + sqrtf(sx * sx + sy * sy);
    }

    /* A path of zero total length is a dot, which is also what sr_line()
     * draws for a degenerate segment. */
    if (!(cum[count - 1u] > 0.0f)) {
        if (cum != stack_cum) free(cum);
        if (cap != SR_CAP_BUTT)
            sr_fill_circle(c, xs[0], ys[0], hw, rgb, alpha);
        return;
    }

    size_t row_w = (size_t)(bx1 - bx0);
    float stack_row[SR_ROW_STACK_PIXELS];
    float *row = stack_row;
    if (row_w > SR_ROW_STACK_PIXELS) {
        row = (float *)malloc(row_w * sizeof(float));
        if (row == NULL) {
            if (cum != stack_cum) free(cum);
            return;
        }
    }

    float period = (float)dash_on + (float)dash_off;
    bool dashed = dash_on >= 0 && dash_off >= 0 && period > 0.0f;

    for (int y = by0; y < by1; y++) {
        memset(row, 0, row_w * sizeof(float));
        float py = (float)y + 0.5f;

        for (size_t i = 0u; i + 1u < count; i++) {
            float ax = xs[i], ay = ys[i];
            float bx = xs[i + 1u], by = ys[i + 1u];
            float len = cum[i + 1u] - cum[i];
            if (!(len > 0.0f)) continue;
            if (py < fminf(ay, by) - pad || py > fmaxf(ay, by) + pad) continue;

            int cap_a = i == 0u ? (int)cap : SR_CAP_ROUND;
            int cap_b = i + 2u == count ? (int)cap : SR_CAP_ROUND;
            int sx = clip_lo((double)fminf(ax, bx) - (double)pad, bx0, bx1);
            int ex = clip_hi((double)fmaxf(ax, bx) + (double)pad, bx0, bx1);

            for (int x = sx; x < ex; x++) {
                float along = 0.0f;
                float cov = segment_coverage(ax, ay, bx, by, len, hw,
                                             (float)x + 0.5f, py,
                                             cap_a, cap_b, &along);
                if (cov <= 0.0f) continue;
                if (dashed &&
                    dash_phase(cum[i] + along + dash_offset, period) >=
                        (float)dash_on)
                    continue;
                size_t k = (size_t)(x - bx0);
                if (cov > row[k]) row[k] = cov;
            }
        }
        blend_cov_row(c, y, bx0, bx1, row, rgb, alpha);
    }

    if (row != stack_row) free(row);
    if (cum != stack_cum) free(cum);
}

void sr_fill_polygon_aa(sr_canvas *c, const float *xs, const float *ys,
                        size_t count, uint32_t rgb, float alpha)
{
    if (!canvas_ok(c) || xs == NULL || ys == NULL || count < 3u ||
        count > SIZE_MAX / sizeof(double) || !(alpha > 0.0f)) return;

    float min_x = xs[0], max_x = xs[0], min_y = ys[0], max_y = ys[0];
    for (size_t i = 0u; i < count; i++) {
        if (!isfinite(xs[i]) || !isfinite(ys[i])) return;
        min_x = fminf(min_x, xs[i]);
        max_x = fmaxf(max_x, xs[i]);
        min_y = fminf(min_y, ys[i]);
        max_y = fmaxf(max_y, ys[i]);
    }
    int bx0 = clip_lo((double)min_x, c->clip_x0, c->clip_x1);
    int bx1 = clip_hi((double)max_x, c->clip_x0, c->clip_x1);
    int by0 = clip_lo((double)min_y, c->clip_y0, c->clip_y1);
    int by1 = clip_hi((double)max_y, c->clip_y0, c->clip_y1);
    if (bx0 >= bx1 || by0 >= by1) return;

    double stack_crossings[POLY_STACK_CROSSINGS];
    double *crossings = stack_crossings;
    if (count > POLY_STACK_CROSSINGS) {
        crossings = (double *)malloc(count * sizeof(double));
        if (crossings == NULL) return;
    }

    size_t row_w = (size_t)(bx1 - bx0);
    float stack_row[SR_ROW_STACK_PIXELS];
    float *row = stack_row;
    if (row_w > SR_ROW_STACK_PIXELS) {
        row = (float *)malloc(row_w * sizeof(float));
        if (row == NULL) {
            if (crossings != stack_crossings) free(crossings);
            return;
        }
    }
    const double share = 1.0 / (double)SR_AA_SUBSAMPLES;

    for (int y = by0; y < by1; y++) {
        memset(row, 0, row_w * sizeof(float));

        for (int s = 0; s < SR_AA_SUBSAMPLES; s++) {
            double py = (double)y + ((double)s + 0.5) * share;
            size_t found = 0u;

            for (size_t i = 0u; i < count; i++) {
                size_t next = i + 1u == count ? 0u : i + 1u;
                double yi = (double)ys[i], yj = (double)ys[next];
                if ((yi <= py) == (yj <= py)) continue;
                crossings[found++] = (double)xs[i] +
                    (py - yi) / (yj - yi) *
                    ((double)xs[next] - (double)xs[i]);
            }
            if (found < 2u) continue;

            for (size_t a = 1u; a < found; a++) {
                double v = crossings[a];
                size_t b = a;
                while (b > 0u && crossings[b - 1u] > v) {
                    crossings[b] = crossings[b - 1u];
                    b--;
                }
                crossings[b] = v;
            }

            for (size_t k = 0u; k + 1u < found; k += 2u) {
                double xa = crossings[k], xb = crossings[k + 1u];
                if (!(xb > xa)) continue;
                int sx = clip_lo(xa, bx0, bx1);
                int ex = clip_hi(xb, bx0, bx1);
                for (int x = sx; x < ex; x++) {
                    double l = xa > (double)x ? xa : (double)x;
                    double r = xb < (double)x + 1.0 ? xb : (double)x + 1.0;
                    if (r > l)
                        row[(size_t)(x - bx0)] += (float)((r - l) * share);
                }
            }
        }
        blend_cov_row(c, y, bx0, bx1, row, rgb, alpha);
    }

    if (row != stack_row) free(row);
    if (crossings != stack_crossings) free(crossings);
}

/* Signed distance to a rounded rectangle: negative inside, zero on the
 * outline.  ex/ey are half-extents and r is already clamped. */
static float round_rect_sd(float px, float py, float cx, float cy,
                           float ex, float ey, float r)
{
    float qx = fabsf(px - cx) - (ex - r);
    float qy = fabsf(py - cy) - (ey - r);
    float mx = qx > 0.0f ? qx : 0.0f;
    float my = qy > 0.0f ? qy : 0.0f;
    float outer = sqrtf(mx * mx + my * my);
    float inner = fmaxf(qx, qy);
    if (inner > 0.0f) inner = 0.0f;
    return outer + inner - r;
}

/* Shared driver for the two rounded-rectangle calls.  band < 0 fills the
 * interior; band >= 0 keeps a stroke of that half-width around the outline. */
static void round_rect_shape(sr_canvas *c, float x, float y, float w, float h,
                             float r, float band, uint32_t rgb, float alpha)
{
    if (!canvas_ok(c) || !isfinite(x) || !isfinite(y) ||
        !isfinite(w) || !isfinite(h) || !isfinite(r) || !isfinite(band) ||
        !(alpha > 0.0f) || !(w > 0.0f) || !(h > 0.0f)) return;

    float ex = w * 0.5f, ey = h * 0.5f;
    float cx = x + ex, cy = y + ey;
    float rr = r;
    if (!(rr > 0.0f)) rr = 0.0f;
    rr = fminf(rr, fminf(ex, ey));

    float pad = (band > 0.0f ? band : 0.0f) + 1.0f;
    int bx0 = clip_lo((double)(cx - ex - pad), c->clip_x0, c->clip_x1);
    int bx1 = clip_hi((double)(cx + ex + pad), c->clip_x0, c->clip_x1);
    int by0 = clip_lo((double)(cy - ey - pad), c->clip_y0, c->clip_y1);
    int by1 = clip_hi((double)(cy + ey + pad), c->clip_y0, c->clip_y1);

    for (int py = by0; py < by1; py++) {
        for (int px = bx0; px < bx1; px++) {
            float d = round_rect_sd((float)px + 0.5f, (float)py + 0.5f,
                                    cx, cy, ex, ey, rr);
            float cov = band < 0.0f ? sat(0.5f - d)
                                    : sat(0.5f - (fabsf(d) - band));
            if (cov > 0.0f) blend_px_unchecked(c, px, py, rgb, alpha * cov);
        }
    }
}

void sr_fill_round_rect(sr_canvas *c, float x, float y, float w, float h,
                        float r, uint32_t rgb, float alpha)
{
    round_rect_shape(c, x, y, w, h, r, -1.0f, rgb, alpha);
}

void sr_stroke_round_rect(sr_canvas *c, float x, float y, float w, float h,
                          float r, float line, uint32_t rgb, float alpha)
{
    float band = line * 0.5f;
    if (!(band > 0.5f)) band = 0.5f;
    round_rect_shape(c, x, y, w, h, r, band, rgb, alpha);
}

typedef struct cubic_sink {
    float *xs;
    float *ys;
    size_t capacity;
    size_t count;
} cubic_sink;

static void cubic_emit(cubic_sink *s, float x, float y)
{
    if (s->count < s->capacity) {
        s->xs[s->count] = x;
        s->ys[s->count] = y;
    }
    if (s->count < SIZE_MAX) s->count++;
}

/* AGG's flatness test: subdivide while the control points sit further than
 * the tolerance from the chord.  The comparison is scaled by the squared
 * chord length so no square root is needed. */
static void flatten_cubic(cubic_sink *s, float x0, float y0,
                          float x1, float y1, float x2, float y2,
                          float x3, float y3, float tol2, int depth)
{
    float dx = x3 - x0, dy = y3 - y0;
    float d1 = fabsf((x1 - x3) * dy - (y1 - y3) * dx);
    float d2 = fabsf((x2 - x3) * dy - (y2 - y3) * dx);
    float dd = d1 + d2;

    if (depth >= SR_CUBIC_MAX_DEPTH ||
        dd * dd <= tol2 * (dx * dx + dy * dy)) {
        cubic_emit(s, x3, y3);
        return;
    }

    float x01 = (x0 + x1) * 0.5f, y01 = (y0 + y1) * 0.5f;
    float x12 = (x1 + x2) * 0.5f, y12 = (y1 + y2) * 0.5f;
    float x23 = (x2 + x3) * 0.5f, y23 = (y2 + y3) * 0.5f;
    float xa = (x01 + x12) * 0.5f, ya = (y01 + y12) * 0.5f;
    float xb = (x12 + x23) * 0.5f, yb = (y12 + y23) * 0.5f;
    float xm = (xa + xb) * 0.5f, ym = (ya + yb) * 0.5f;

    flatten_cubic(s, x0, y0, x01, y01, xa, ya, xm, ym, tol2, depth + 1);
    flatten_cubic(s, xm, ym, xb, yb, x23, y23, x3, y3, tol2, depth + 1);
}

size_t sr_flatten_cubic(float x0, float y0, float x1, float y1,
                        float x2, float y2, float x3, float y3,
                        float tolerance, float *xs, float *ys, size_t capacity)
{
    if (!isfinite(x0) || !isfinite(y0) || !isfinite(x1) || !isfinite(y1) ||
        !isfinite(x2) || !isfinite(y2) || !isfinite(x3) || !isfinite(y3))
        return 0u;
    if (capacity > 0u && (xs == NULL || ys == NULL)) return 0u;

    float tol = tolerance;
    if (!(tol >= 0.03125f)) tol = 0.03125f;

    cubic_sink sink = { xs, ys, capacity, 0u };
    cubic_emit(&sink, x0, y0);
    flatten_cubic(&sink, x0, y0, x1, y1, x2, y2, x3, y3, tol * tol, 0);
    return sink.count;
}

/* ------------------------------------------------------------------ text */

static int text_width_for(size_t length, int advance, int scale)
{
    if (scale < 1) scale = 1;
    if (advance <= 0 || scale > INT_MAX / advance) return INT_MAX;
    {
        const int per_character = advance * scale;
        if (length > (size_t)INT_MAX / (size_t)per_character) return INT_MAX;
        return (int)length * per_character;
    }
}

int sr_text_width(const char *s, int scale)
{
    return s == NULL ? 0 : text_width_for(strlen(s), SR_FONT_W, scale);
}

const uint8_t *sr_font_glyph(unsigned char ch)
{
    if (ch < 32u || ch > 126u) ch = (unsigned char)'?';
    return font8x16[ch - 32u];
}

static void draw_glyph(sr_canvas *c, double x, double y,
                       const unsigned char *glyph, uint32_t rgb, float alpha,
                       int scale, int height)
{
    for (int gy = 0; gy < height; gy++) {
        const unsigned row = glyph[gy];
        const double top = y + (double)gy * (double)scale;
        const double bottom = top + (double)scale;
        const int y0 = clip_lo(top, c->clip_y0, c->clip_y1);
        const int y1 = clip_hi(bottom, c->clip_y0, c->clip_y1);

        if (y0 >= y1) continue;
        for (int gx = 0; gx < SR_FONT_W; gx++) {
            int x0;
            int x1;
            const double left = x + (double)gx * (double)scale;
            const double right = left + (double)scale;

            if (!((row >> (7 - gx)) & 1u)) continue;
            x0 = clip_lo(left, c->clip_x0, c->clip_x1);
            x1 = clip_hi(right, c->clip_x0, c->clip_x1);
            for (int py = y0; py < y1; ++py)
                for (int px = x0; px < x1; ++px)
                    blend_px_unchecked(c, px, py, rgb, alpha);
        }
    }
}

/* Skip complete glyph cells to the left of the active clip.  Besides avoiding
 * needless work, this bounds calls whose finite x coordinate is extremely
 * negative instead of walking billions of invisible characters. */
static const char *skip_clipped_text(const char *s, double *x,
                                     double advance, int clip_left)
{
    double cells;
    size_t length;
    size_t skip;

    if (*x >= (double)clip_left) return s;
    cells = floor(((double)clip_left - *x) / advance);
    if (!(cells > 0.0)) return s;
    length = strlen(s);
    if (cells >= (double)length) return s + length;
    skip = (size_t)cells;
    *x += (double)skip * advance;
    return s + skip;
}

/* The fixed-face entry points delegate to the selectable-face path: the
 * SR_FONT_FIXED_8X16 descriptor carries exactly SR_FONT_W, SR_FONT_H, and
 * the font8x16 rows, so the drawing is byte-identical and the clipping
 * logic lives in one place. */
void sr_text(sr_canvas *c, float x, float y, const char *s,
             uint32_t rgb, float alpha, int scale)
{
    sr_text_in(SR_FONT_FIXED_8X16, c, x, y, s, rgb, alpha, scale);
}

void sr_text_center(sr_canvas *c, float cx, float y, const char *s,
                    uint32_t rgb, float alpha, int scale)
{
    sr_text_center_in(SR_FONT_FIXED_8X16, c, cx, y, s, rgb, alpha, scale);
}

void sr_text_outlined(sr_canvas *c, float x, float y, const char *s,
                      uint32_t rgb, float alpha, int scale)
{
    sr_text(c, x - 1.0f, y, s, 0x000000u, alpha, scale);
    sr_text(c, x + 1.0f, y, s, 0x000000u, alpha, scale);
    sr_text(c, x, y - 1.0f, s, 0x000000u, alpha, scale);
    sr_text(c, x, y + 1.0f, s, 0x000000u, alpha, scale);
    sr_text(c, x, y, s, rgb, alpha, scale);
}

void sr_text_shadow(sr_canvas *c, float x, float y, const char *s,
                    uint32_t rgb, float alpha, int scale)
{
    if (scale < 1) scale = 1;
    sr_text(c, x + (float)scale, y + (float)scale, s,
            0x000000u, alpha * 0.75f, scale);
    sr_text(c, x, y, s, rgb, alpha, scale);
}

/* ---- Selectable faces ---------------------------------------------- */

typedef struct sr_font_desc {
    const unsigned char (*glyphs)[14];
    const unsigned char (*glyphs16)[16];
    int advance;
    int height;
} sr_font_desc;

static const sr_font_desc *font_desc(sr_font_id font)
{
    static const sr_font_desc fixed = {NULL, font8x16, SR_FONT_W, SR_FONT_H};
    static const sr_font_desc compact = {font7x14, NULL, 8, 14};
    if (font == SR_FONT_FIXED_8X16) return &fixed;
    if (font == SR_FONT_COMPACT_7X14) return &compact;
    return NULL;
}

int sr_font_advance(sr_font_id font)
{
    const sr_font_desc *d = font_desc(font);
    return d ? d->advance : 0;
}

int sr_font_height(sr_font_id font)
{
    const sr_font_desc *d = font_desc(font);
    return d ? d->height : 0;
}

const uint8_t *sr_font_glyph_in(sr_font_id font, unsigned char ch)
{
    const sr_font_desc *d = font_desc(font);
    if (d == NULL) return NULL;
    if (ch < 32u || ch > 126u) ch = (unsigned char)'?';
    return d->glyphs16 ? d->glyphs16[ch - 32u] : d->glyphs[ch - 32u];
}

int sr_text_width_in(sr_font_id font, const char *s, int scale)
{
    const sr_font_desc *d = font_desc(font);
    if (d == NULL || s == NULL) return 0;
    return text_width_for(strlen(s), d->advance, scale);
}

void sr_text_in(sr_font_id font, sr_canvas *c, float x, float y,
                const char *s, uint32_t rgb, float alpha, int scale)
{
    const sr_font_desc *d = font_desc(font);
    double ix;
    double iy;
    double advance;

    if (d == NULL || !canvas_ok(c) || s == NULL ||
        !isfinite(x) || !isfinite(y) || !(alpha > 0.0f)) return;
    if (scale < 1) scale = 1;
    ix = trunc((double)x);
    iy = trunc((double)y);
    advance = (double)d->advance * (double)scale;
    if (iy >= (double)c->clip_y1 ||
        iy + (double)d->height * (double)scale <=
            (double)c->clip_y0) return;
    s = skip_clipped_text(s, &ix, advance, c->clip_x0);
    for (; *s; s++) {
        if (ix >= (double)c->clip_x1) break;
        draw_glyph(c, ix, iy, sr_font_glyph_in(font, (unsigned char)*s),
                   rgb, alpha, scale, d->height);
        ix += advance;
    }
}

void sr_text_center_in(sr_font_id font, sr_canvas *c, float cx, float y,
                       const char *s, uint32_t rgb, float alpha, int scale)
{
    if (s == NULL) return;
    sr_text_in(font, c, cx - (float)sr_text_width_in(font, s, scale) / 2.0f,
               y, s, rgb, alpha, scale);
}

/* ----------------------------------------------------------------- blits */

typedef struct blit_region {
    int x0;
    int y0;
    int x1;
    int y1;
} blit_region;

static bool source_blit_region(const sr_canvas *dst, const sr_canvas *src,
                               int x, int y, blit_region *region)
{
    const int64_t right = (int64_t)x + src->w;
    const int64_t bottom = (int64_t)y + src->h;
    const int64_t visible_width = (int64_t)dst->w - x;
    const int64_t visible_height = (int64_t)dst->h - y;

    if (right <= 0 || bottom <= 0 || x >= dst->w || y >= dst->h)
        return false;
    region->x0 = x < 0 ? (int)(-(int64_t)x) : 0;
    region->y0 = y < 0 ? (int)(-(int64_t)y) : 0;
    region->x1 = (int64_t)src->w < visible_width
        ? src->w : (int)visible_width;
    region->y1 = (int64_t)src->h < visible_height
        ? src->h : (int)visible_height;
    return region->x0 < region->x1 && region->y0 < region->y1;
}

void sr_blit(sr_canvas *dst, const sr_canvas *src, int x, int y)
{
    blit_region region;
    int first;
    int stop;
    int step;

    if (!canvas_ok(dst) || !canvas_ok(src)) return;
    if (!source_blit_region(dst, src, x, y, &region)) return;
    first = region.y0;
    stop = region.y1;
    step = 1;
    if (dst->px == src->px && y > 0) {
        first = region.y1 - 1;
        stop = region.y0 - 1;
        step = -1;
    }
    for (int sy = first; sy != stop; sy += step) {
        const uint32_t *from = &src->px[(size_t)sy * (size_t)src->w +
                                        (size_t)region.x0];
        uint32_t *to = &dst->px[(size_t)(y + sy) * (size_t)dst->w +
                                (size_t)(x + region.x0)];
        memmove(to, from,
                (size_t)(region.x1 - region.x0) * sizeof(uint32_t));
    }
}

/* Composites one premultiplied source pixel over the destination; ga is the
 * uniform alpha in [0,255].  Matches the sprite compositor the blits were
 * extracted from. */
static void composite_px(uint32_t *to, uint32_t s, int ga)
{
    int sa = ((int)(s >> 24) * ga) / 255;
    if (sa <= 0) return;
    if (sa >= 255) {
        *to = s;
        return;
    }
    int inv = 255 - sa;
    uint32_t d = *to;
    int r = ((int)((s >> 16) & 255u) * ga) / 255 +
            ((int)((d >> 16) & 255u) * inv) / 255;
    int g = ((int)((s >> 8) & 255u) * ga) / 255 +
            ((int)((d >> 8) & 255u) * inv) / 255;
    int b = ((int)(s & 255u) * ga) / 255 + ((int)(d & 255u) * inv) / 255;
    int a = sa + ((int)(d >> 24) * inv) / 255;
    *to = ((uint32_t)a << 24) | ((uint32_t)r << 16) |
          ((uint32_t)g << 8) | (uint32_t)b;
}

static void composite_tint_px(uint32_t *to, uint32_t s, int ga,
                              uint32_t rgb)
{
    int sa = ((int)(s >> 24) * ga) / 255;
    if (sa <= 0) return;
    if (sa >= 255) {
        *to = UINT32_C(0xff000000) | (rgb & UINT32_C(0x00ffffff));
        return;
    }
    int inv = 255 - sa;
    uint32_t d = *to;
    int tr = (int)((rgb >> 16) & 255u);
    int tg = (int)((rgb >> 8) & 255u);
    int tb = (int)(rgb & 255u);
    int r = (tr * sa + (int)((d >> 16) & 255u) * inv) / 255;
    int g = (tg * sa + (int)((d >> 8) & 255u) * inv) / 255;
    int b = (tb * sa + (int)(d & 255u) * inv) / 255;
    int a = sa + ((int)(d >> 24) * inv) / 255;
    *to = ((uint32_t)a << 24) | ((uint32_t)r << 16) |
          ((uint32_t)g << 8) | (uint32_t)b;
}

/* Overlap-safe iteration order for the unscaled compositing blits: when
 * source and destination share storage and the copy shifts right or down,
 * walk that axis backwards so no source pixel is overwritten before it is
 * read. */
typedef struct blit_iter {
    int y_first;
    int y_stop;
    int y_step;
    int x_first;
    int x_stop;
    int x_step;
} blit_iter;

static blit_iter overlap_blit_iter(const sr_canvas *dst,
                                   const sr_canvas *src, int x, int y,
                                   const blit_region *region)
{
    blit_iter it = {region->y0, region->y1, 1,
                    region->x0, region->x1, 1};

    if (dst->px == src->px) {
        if (y > 0) {
            it.y_first = region->y1 - 1;
            it.y_stop = region->y0 - 1;
            it.y_step = -1;
        }
        if (x > 0) {
            it.x_first = region->x1 - 1;
            it.x_stop = region->x0 - 1;
            it.x_step = -1;
        }
    }
    return it;
}

void sr_blit_alpha(sr_canvas *dst, const sr_canvas *src, int x, int y,
                   float alpha)
{
    blit_region region;

    if (!canvas_ok(dst) || !canvas_ok(src) || alpha <= 0.0f) return;
    if (!source_blit_region(dst, src, x, y, &region)) return;
    int ga = (int)(clampf(alpha, 0.0f, 1.0f) * 255.0f + 0.5f);
    if (ga <= 0) return;
    const blit_iter it = overlap_blit_iter(dst, src, x, y, &region);
    for (int sy = it.y_first; sy != it.y_stop; sy += it.y_step) {
        for (int sx = it.x_first; sx != it.x_stop; sx += it.x_step) {
            uint32_t s = src->px[(size_t)sy * (size_t)src->w + (size_t)sx];
            composite_px(&dst->px[(size_t)(y + sy) * (size_t)dst->w +
                                  (size_t)(x + sx)], s, ga);
        }
    }
}

void sr_blit_tint(sr_canvas *dst, const sr_canvas *src, int x, int y,
                  uint32_t rgb, float alpha)
{
    blit_region region;

    if (!canvas_ok(dst) || !canvas_ok(src) || alpha <= 0.0f) return;
    if (!source_blit_region(dst, src, x, y, &region)) return;
    int ga = (int)(clampf(alpha, 0.0f, 1.0f) * 255.0f + 0.5f);
    if (ga <= 0) return;
    const blit_iter it = overlap_blit_iter(dst, src, x, y, &region);
    for (int sy = it.y_first; sy != it.y_stop; sy += it.y_step) {
        for (int sx = it.x_first; sx != it.x_stop; sx += it.x_step) {
            uint32_t s = src->px[(size_t)sy * (size_t)src->w + (size_t)sx];
            uint32_t *to = &dst->px[(size_t)(y + sy) * (size_t)dst->w +
                                    (size_t)(x + sx)];
            composite_tint_px(to, s, ga, rgb);
        }
    }
}

void sr_blit_scaled(sr_canvas *dst, const sr_canvas *src, int x, int y,
                    int w, int h, float alpha)
{
    int dx0;
    int dy0;
    int dx1;
    int dy1;
    int source_x;
    int source_x_step;
    int source_x_remainder;
    int source_y;
    int source_y_step;
    int source_y_remainder;
    int64_t x_error_start;
    int64_t y_error;

    if (!canvas_ok(dst) || !canvas_ok(src) || w <= 0 || h <= 0 ||
        alpha <= 0.0f) return;
    if (dst->px == src->px) return;  /* aliased storage: same-buffer no-op */
    if ((int64_t)x + w <= 0 || (int64_t)y + h <= 0 ||
        x >= dst->w || y >= dst->h) return;
    int ga = (int)(clampf(alpha, 0.0f, 1.0f) * 255.0f + 0.5f);
    if (ga <= 0) return;
    dx0 = x < 0 ? (int)(-(int64_t)x) : 0;
    dy0 = y < 0 ? (int)(-(int64_t)y) : 0;
    dx1 = (int64_t)w < (int64_t)dst->w - x
        ? w : (int)((int64_t)dst->w - x);
    dy1 = (int64_t)h < (int64_t)dst->h - y
        ? h : (int)((int64_t)dst->h - y);
    {
        const int64_t numerator = (int64_t)dx0 * src->w;
        source_x = (int)(numerator / w);
        x_error_start = numerator % w;
    }
    source_x_step = src->w / w;
    source_x_remainder = src->w % w;
    {
        const int64_t numerator = (int64_t)dy0 * src->h;
        source_y = (int)(numerator / h);
        y_error = numerator % h;
    }
    source_y_step = src->h / h;
    source_y_remainder = src->h % h;
    for (int dy = dy0; dy < dy1; dy++) {
        int sx = source_x;
        int64_t x_error = x_error_start;
        for (int dx = dx0; dx < dx1; dx++) {
            uint32_t s = src->px[(size_t)source_y * (size_t)src->w +
                                 (size_t)sx];
            composite_px(&dst->px[(size_t)(y + dy) * (size_t)dst->w +
                                  (size_t)(x + dx)], s, ga);
            sx += source_x_step;
            x_error += source_x_remainder;
            if (x_error >= w) {
                ++sx;
                x_error -= w;
            }
        }
        source_y += source_y_step;
        y_error += source_y_remainder;
        if (y_error >= h) {
            ++source_y;
            y_error -= h;
        }
    }
}

void sr_blit_transformed(sr_canvas *dst, const sr_canvas *src, int x, int y,
                         uint8_t transform, float alpha, bool tint_enabled,
                         uint32_t rgb)
{
    const uint8_t known = SR_TRANSFORM_FLIP_HORIZONTAL |
                          SR_TRANSFORM_FLIP_VERTICAL |
                          SR_TRANSFORM_FLIP_DIAGONAL;
    int output_w;
    int output_h;
    int tx0;
    int ty0;
    int tx1;
    int ty1;
    int ga;

    if (!canvas_ok(dst) || !canvas_ok(src) || !(alpha > 0.0f) ||
        (transform & (uint8_t)~known) != 0u) return;
    if (dst->px == src->px) return;  /* aliased storage: same-buffer no-op */
    output_w = (transform & SR_TRANSFORM_FLIP_DIAGONAL) != 0u
        ? src->h : src->w;
    output_h = (transform & SR_TRANSFORM_FLIP_DIAGONAL) != 0u
        ? src->w : src->h;
    if ((int64_t)x + output_w <= 0 || (int64_t)y + output_h <= 0 ||
        x >= dst->w || y >= dst->h) return;
    ga = (int)(clampf(alpha, 0.0f, 1.0f) * 255.0f + 0.5f);
    if (ga <= 0) return;
    tx0 = x < 0 ? (int)(-(int64_t)x) : 0;
    ty0 = y < 0 ? (int)(-(int64_t)y) : 0;
    tx1 = (int64_t)output_w < (int64_t)dst->w - x
        ? output_w : (int)((int64_t)dst->w - x);
    ty1 = (int64_t)output_h < (int64_t)dst->h - y
        ? output_h : (int)((int64_t)dst->h - y);

    for (int ty = ty0; ty < ty1; ty++) {
        for (int tx = tx0; tx < tx1; tx++) {
            int sx = tx;
            int sy = ty;
            int dx;
            int dy;
            uint32_t s;
            uint32_t *to;

            /* Invert forward diagonal, horizontal, vertical order. */
            if ((transform & SR_TRANSFORM_FLIP_HORIZONTAL) != 0u)
                sx = output_w - 1 - sx;
            if ((transform & SR_TRANSFORM_FLIP_VERTICAL) != 0u)
                sy = output_h - 1 - sy;
            if ((transform & SR_TRANSFORM_FLIP_DIAGONAL) != 0u) {
                int temporary = sx;
                sx = sy;
                sy = temporary;
            }
            dx = (int)((int64_t)x + tx);
            dy = (int)((int64_t)y + ty);
            s = src->px[(size_t)sy * (size_t)src->w + (size_t)sx];
            to = &dst->px[(size_t)dy * (size_t)dst->w + (size_t)dx];
            if (tint_enabled)
                composite_tint_px(to, s, ga, rgb);
            else
                composite_px(to, s, ga);
        }
    }
}

/* Opaque-black rectangle used for the letterbox bars; matches the bytes
 * sr_clear(dst, 0x000000) writes. */
static void clear_bar(sr_canvas *dst, int x0, int y0, int x1, int y1)
{
    for (int y = y0; y < y1; y++) {
        uint32_t *row = &dst->px[(size_t)y * (size_t)dst->w];

        for (int x = x0; x < x1; x++)
            row[x] = 0xff000000u;
    }
}

void sr_scale_canvas(sr_canvas *dst, const sr_canvas *src)
{
    int dw;
    int dh;
    int64_t scaled_height;

    if (!canvas_ok(dst)) return;
    if (canvas_ok(src) && dst->px == src->px) return;
    if (!canvas_ok(src)) {
        sr_clear(dst, 0x000000u);
        return;
    }
    dw = dst->w;
    scaled_height = (int64_t)dw * src->h / src->w;
    if (scaled_height > dst->h) {
        dh = dst->h;
        dw = (int)((int64_t)dh * src->w / src->h);
    } else {
        dh = (int)scaled_height;
    }
    if (dw <= 0 || dh <= 0) {
        sr_clear(dst, 0x000000u);
        return;
    }
    int off_x = (dst->w - dw) / 2;
    int off_y = (dst->h - dh) / 2;
    /* The scale loop stores to every pixel of the fitted rectangle, so
     * only the letterbox bars around it need clearing; at most one axis
     * has bars, but all four strips together tile the exact complement. */
    clear_bar(dst, 0, 0, off_x, dst->h);
    clear_bar(dst, off_x + dw, 0, dst->w, dst->h);
    clear_bar(dst, off_x, 0, off_x + dw, off_y);
    clear_bar(dst, off_x, off_y + dh, off_x + dw, dst->h);
    int sy = 0;
    int64_t y_error = 0;
    const int sy_step = src->h / dh;
    const int64_t sy_remainder = src->h % dh;
    const int sx_step = src->w / dw;
    const int64_t sx_remainder = src->w % dw;
    for (int y = 0; y < dh; y++) {
        int sx = 0;
        int64_t x_error = 0;
        for (int x = 0; x < dw; x++) {
            uint32_t s = src->px[(size_t)sy * (size_t)src->w + (size_t)sx];
            dst->px[(size_t)(off_y + y) * (size_t)dst->w +
                    (size_t)(off_x + x)] = 0xff000000u | (s & 0x00ffffffu);
            sx += sx_step;
            x_error += sx_remainder;
            if (x_error >= dw) {
                ++sx;
                x_error -= dw;
            }
        }
        sy += sy_step;
        y_error += sy_remainder;
        if (y_error >= dh) {
            ++sy;
            y_error -= dh;
        }
    }
}

/* ------------------------------------------------------------------- ppm */

#define PPM_CHUNK_PIXELS 4096u

static bool ppm_token(FILE *file, char *buffer, size_t capacity)
{
    int byte;
    size_t length = 0u;
    if (capacity < 2u) return false;
    do {
        byte = fgetc(file);
        if (byte == '#') {
            do byte = fgetc(file); while (byte != '\n' && byte != EOF);
        }
    } while (byte != EOF && isspace((unsigned char)byte));
    if (byte == EOF) return false;
    do {
        if (length + 1u >= capacity) return false;
        buffer[length++] = (char)byte;
        byte = fgetc(file);
    } while (byte != EOF && !isspace((unsigned char)byte));
    buffer[length] = '\0';
    return length > 0u;
}

static bool parse_positive_int(const char *text, int *value)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed <= 0 ||
        parsed > INT_MAX)
        return false;
    *value = (int)parsed;
    return true;
}

bool sr_load_ppm(sr_canvas *c, const char *path)
{
    FILE *file = NULL;
    char token[64];
    unsigned char bytes[PPM_CHUNK_PIXELS * 3u];
    int width, height, maxval;
    int failure = 0;
    sr_canvas loaded = {0};
    bool ok = false;

    if (c == NULL || path == NULL) {
        errno = EINVAL;
        return false;
    }
    *c = (sr_canvas){0};
    file = fopen(path, "rb");
    if (file == NULL) return false;
    errno = 0;
    if (!ppm_token(file, token, sizeof token) || strcmp(token, "P6") != 0 ||
        !ppm_token(file, token, sizeof token) ||
        !parse_positive_int(token, &width) ||
        !ppm_token(file, token, sizeof token) ||
        !parse_positive_int(token, &height) ||
        !ppm_token(file, token, sizeof token) ||
        !parse_positive_int(token, &maxval) || maxval != 255) {
        failure = EINVAL;
        goto done;
    }
    if (!dimensions_ok(width, height, NULL)) {
        failure = EOVERFLOW;
        goto done;
    }
    errno = 0;
    if (!sr_canvas_init(&loaded, width, height)) {
        failure = errno != 0 ? errno : ENOMEM;
        goto done;
    }

    size_t pixels = (size_t)width * (size_t)height;
    for (size_t offset = 0u; offset < pixels;) {
        const size_t remaining = pixels - offset;
        const size_t chunk = remaining < PPM_CHUNK_PIXELS
            ? remaining : PPM_CHUNK_PIXELS;

        if (fread(bytes, 3u, chunk, file) != chunk) {
            failure = ferror(file) && errno != 0 ? errno :
                      ferror(file) ? EIO : EINVAL;
            goto done;
        }
        for (size_t index = 0u; index < chunk; ++index) {
            loaded.px[offset + index] = UINT32_C(0xff000000) |
                sr_rgb(bytes[index * 3u], bytes[index * 3u + 1u],
                       bytes[index * 3u + 2u]);
        }
        offset += chunk;
    }
    *c = loaded;
    loaded = (sr_canvas){0};
    ok = true;

done:
    sr_canvas_free(&loaded);
    if (fclose(file) != 0) {
        if (ok) sr_canvas_free(c);
        if (failure == 0) failure = errno != 0 ? errno : EIO;
        ok = false;
    }
    errno = ok ? 0 : failure != 0 ? failure : EIO;
    return ok;
}

bool sr_write_ppm(const sr_canvas *c, const char *path)
{
    unsigned char bytes[PPM_CHUNK_PIXELS * 3u];
    int failure = 0;
    bool ok = true;

    if (!canvas_ok(c) || path == NULL) {
        errno = EINVAL;
        return false;
    }
    FILE *file = fopen(path, "wb");
    if (file == NULL) return false;
    errno = 0;
    if (fprintf(file, "P6\n%d %d\n255\n", c->w, c->h) < 0) {
        failure = errno != 0 ? errno : EIO;
        ok = false;
    }
    size_t n = (size_t)c->w * (size_t)c->h;
    for (size_t offset = 0u; ok && offset < n;) {
        const size_t remaining = n - offset;
        const size_t chunk = remaining < PPM_CHUNK_PIXELS
            ? remaining : PPM_CHUNK_PIXELS;

        pack_rgb_pixels(c->px + offset, bytes, chunk);
        if (fwrite(bytes, 3u, chunk, file) != chunk) {
            failure = errno != 0 ? errno : EIO;
            ok = false;
        }
        offset += chunk;
    }
    if (ferror(file)) {
        if (failure == 0) failure = errno != 0 ? errno : EIO;
        ok = false;
    }
    if (fclose(file) != 0) {
        if (failure == 0) failure = errno != 0 ? errno : EIO;
        ok = false;
    }
    errno = ok ? 0 : failure != 0 ? failure : EIO;
    return ok;
}
