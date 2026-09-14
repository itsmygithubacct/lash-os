/* SPDX-License-Identifier: MIT */
/* termpixel_pong — C loadable Pong built on the termpixel substrate.
 *
 * Plays the termpixel_pong Python reference's game entirely inside the bash-os
 * Bash binary: no Python/pygame/subprocess/sound/recording. Uses the
 * termpixel.h helper API for the canvas, primitives, font, raw input, and
 * frame pacing. The builtin symbol is termpixel_pong (underscore); the user
 * command is termpixel-pong.
 *
 * See research/bash-os/IMPL-PLANS/termpixel/02-termpixel-pong-c-loadable.md.
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "termpixel.h"
#include "loadables.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define W 80
#define H 80
#define PADDLE_W 2
#define PADDLE_H 12
#define PADDLE_SPEED 100.0
#define BALL_SIZE 2
#define BALL_SPEED 80.0
#define BALL_MAXSPEED 150.0
#define SERVE_DELAY 1.0

/* deterministic PRNG (xorshift32) owned by the loadable */
static unsigned int rng_state = 1u;
static void rng_seed (unsigned int s) { rng_state = s ? s : 1u; }
static unsigned int rng_next (void) {
    unsigned int x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return rng_state = x;
}
static double rng_uniform (double lo, double hi) {
    return lo + (hi - lo) * ((double) (rng_next () & 0xffffff) / (double) 0x1000000);
}

typedef struct {
    double reaction, accuracy; int error_margin;
} ai_cfg;

typedef struct {
    double lx, ly, rx, ry;     /* paddle top-left (float) */
    double bx, by, bvx, bvy;    /* ball pos + velocity */
    double bspeed;
    int lscore, rscore;
    int serving; double serve_t;
    int serve_dir;              /* +1 serve toward right, -1 toward left */
    int paused, over;
    int ai; ai_cfg ai_c; double ai_target; double ai_timer;
    int two_player;
    int winning;
} game;

static void serve (game *g, int dir) {
    g->bx = W / 2.0; g->by = H / 2.0;
    g->bspeed = BALL_SPEED;
    double ang = rng_uniform (-45, 45) * M_PI / 180.0;
    g->bvx = dir * g->bspeed * cos (ang);
    g->bvy = g->bspeed * sin (ang);
    g->serving = 1; g->serve_t = 0.0; g->serve_dir = dir;
}

static void game_init (game *g, int ai, ai_cfg c, int two_player, int winning, int serve_dir) {
    memset (g, 0, sizeof *g);
    g->lx = 5; g->ly = H / 2.0 - 6;
    g->rx = W - 7; g->ry = H / 2.0 - 6;
    g->ai = ai; g->ai_c = c; g->two_player = two_player; g->winning = winning;
    serve (g, serve_dir);
}

static void clampd (double *v, double lo, double hi) { if (*v < lo) *v = lo; if (*v > hi) *v = hi; }

static int aabb (double ax, double ay, double aw, double ah,
                 double bx, double by, double bw, double bh) {
    return ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
}

static void paddle_bounce (game *g, double paddle_y, int dir) {
    double hit = (g->by + BALL_SIZE / 2.0 - paddle_y) / (double) PADDLE_H;  /* 0..1 */
    clampd (&hit, 0, 1);
    double ang = (hit - 0.5) * 2.0 * 60.0 * M_PI / 180.0;   /* -60..60 deg */
    g->bspeed *= 1.05; if (g->bspeed > BALL_MAXSPEED) g->bspeed = BALL_MAXSPEED;
    g->bvx = dir * g->bspeed * cos (ang);
    g->bvy = g->bspeed * sin (ang);
}

static void update (game *g, double dt, int up_l, int dn_l, int up_r, int dn_r) {
    if (g->paused || g->over) return;
    if (up_l) g->ly -= PADDLE_SPEED * dt;
    if (dn_l) g->ly += PADDLE_SPEED * dt;
    if (!g->ai) {
        if (up_r) g->ry -= PADDLE_SPEED * dt;
        if (dn_r) g->ry += PADDLE_SPEED * dt;
    } else {
        g->ai_timer += dt;
        if (g->ai_timer >= 0.1) {
            g->ai_timer = 0;
            double predict = g->by;
            if (rng_uniform (0, 1) > g->ai_c.accuracy)
                predict += rng_uniform (-g->ai_c.error_margin, g->ai_c.error_margin);
            g->ai_target = predict - PADDLE_H / 2.0;
        }
        double diff = g->ai_target - g->ry;
        double step = PADDLE_SPEED * g->ai_c.reaction * dt;
        if (fabs (diff) <= step) g->ry = g->ai_target;
        else g->ry += (diff > 0 ? step : -step);
    }
    clampd (&g->ly, 0, H - PADDLE_H);
    clampd (&g->ry, 0, H - PADDLE_H);

    if (g->serving) {
        g->serve_t += dt;
        if (g->serve_t < SERVE_DELAY) return;
        g->serving = 0;
    }
    g->bx += g->bvx * dt; g->by += g->bvy * dt;

    if (g->by <= 0) { g->by = 0; g->bvy = -g->bvy; }
    if (g->by >= H - BALL_SIZE) { g->by = H - BALL_SIZE; g->bvy = -g->bvy; }

    if (g->bvx < 0 && aabb (g->bx, g->by, BALL_SIZE, BALL_SIZE, g->lx, g->ly, PADDLE_W, PADDLE_H)) {
        g->bx = g->lx + PADDLE_W; paddle_bounce (g, g->ly, +1);
    }
    if (g->bvx > 0 && aabb (g->bx, g->by, BALL_SIZE, BALL_SIZE, g->rx, g->ry, PADDLE_W, PADDLE_H)) {
        g->bx = g->rx - BALL_SIZE; paddle_bounce (g, g->ry, -1);
    }
    if (g->bx + BALL_SIZE < 0) { g->rscore++; if (g->rscore >= g->winning) g->over = 1; else serve (g, +1); }
    else if (g->bx > W) { g->lscore++; if (g->lscore >= g->winning) g->over = 1; else serve (g, -1); }
}

static void render (game *g, btp_canvas *c) {
    btp_clear (c, 0, 0, 0);
    for (int y = 0; y < H; y += 4)               /* center dashed line */
        btp_draw_rect (c, W / 2 - 1, y, 2, 2, 120, 120, 120, 1);
    btp_draw_rect (c, (int) g->lx, (int) g->ly, PADDLE_W, PADDLE_H, 255, 255, 255, 1);
    btp_draw_rect (c, (int) g->rx, (int) g->ry, PADDLE_W, PADDLE_H, 255, 255, 255, 1);
    btp_draw_rect (c, (int) g->bx, (int) g->by, BALL_SIZE, BALL_SIZE, 255, 255, 255, 1);
    char s[8];
    snprintf (s, sizeof s, "%d", g->lscore); btp_draw_text3x5 (c, s, 30, 5, 255, 255, 255);
    snprintf (s, sizeof s, "%d", g->rscore); btp_draw_text3x5 (c, s, 45, 5, 255, 255, 255);
    btp_draw_text3x5 (c, "W S", 2, 2, 160, 160, 160);
    if (g->ai) btp_draw_text3x5 (c, "AI", 62, 2, 160, 160, 160);
    else btp_draw_text3x5 (c, "UP DOWN", 50, 2, 160, 160, 160);
    if (g->serving) btp_draw_text3x5 (c, "SERVING", 25, 35, 220, 220, 80);
    if (g->over) {
        btp_draw_text3x5 (c, "GAME OVER", 22, 30, 255, 80, 80);
        btp_draw_text3x5 (c, g->lscore > g->rscore ? "LEFT WINS" : (g->ai ? "AI WINS" : "RIGHT WINS"),
                          20, 40, 255, 255, 255);
        btp_draw_text3x5 (c, "PRESS ENTER", 18, 50, 200, 200, 200);
    }
}

int
termpixel_pong_builtin (WORD_LIST *list)
{
    int ai = 0, two_player = 1, fps = 60, frames = -1, winning = 5;
    int dump = 0, selftest = 0; unsigned int seed = 1;
    ai_cfg c = { 1.0, 0.95, 2 };       /* default hard if --ai bare */

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *a = p->word->word;
        if (!strncmp (a, "--ai", 4)) {
            ai = 1; two_player = 0;
            const char *d = a[4] == '=' ? a + 5 : "medium";
            if      (!strcmp (d, "easy"))   { c.reaction = 0.6; c.accuracy = 0.7;  c.error_margin = 8; }
            else if (!strcmp (d, "medium")) { c.reaction = 0.8; c.accuracy = 0.85; c.error_margin = 4; }
            else if (!strcmp (d, "hard"))   { c.reaction = 1.0; c.accuracy = 0.95; c.error_margin = 2; }
            else { builtin_error ("invalid AI difficulty: %s", d); return 2; }
        }
        else if (!strcmp (a, "--two-player")) { two_player = 1; ai = 0; }
        else if (!strcmp (a, "--no-sound")) { /* no-op v1 */ }
        else if (!strcmp (a, "--dump-frame")) dump = 1;
        else if (!strcmp (a, "--selftest")) selftest = 1;
        else if (!strcmp (a, "--fps") && p->next) { p = p->next; fps = atoi (p->word->word); }
        else if (!strcmp (a, "--frames") && p->next) { p = p->next; frames = atoi (p->word->word); }
        else if (!strcmp (a, "--seed") && p->next) { p = p->next; seed = (unsigned) strtoul (p->word->word, NULL, 10); }
        else if (!strcmp (a, "--winning-score") && p->next) { p = p->next; winning = atoi (p->word->word); }
        else if (!strcmp (a, "--help") || !strcmp (a, "-h")) { builtin_usage (); return EXECUTION_SUCCESS; }
        else { builtin_error ("unknown option: %s", a); return EX_USAGE; }
    }
    if (fps < 1) fps = 60; if (winning < 1) winning = 5;

    if (selftest) {
        btp_canvas tc; if (btp_canvas_init (&tc, W, H) != 0) { builtin_error ("canvas init"); return EXECUTION_FAILURE; }
        rng_seed (1); game g; game_init (&g, 0, c, 1, winning, +1);
        for (int i = 0; i < 30; i++) update (&g, 1.0 / 60, 1, 0, 0, 1);
        render (&g, &tc);
        int fd = open ("/dev/null", 1); int rr = btp_render_ansi_fd (&tc, fd >= 0 ? fd : 1);
        if (fd >= 0) close (fd);
        btp_canvas_free (&tc);
        if (rr != 0) { builtin_error ("render failed"); return EXECUTION_FAILURE; }
        printf ("termpixel_pong selftest OK\n");
        return EXECUTION_SUCCESS;
    }

    rng_seed (seed);
    btp_canvas canvas;
    if (btp_canvas_init (&canvas, W, H) != 0) { builtin_error ("canvas init failed"); return EXECUTION_FAILURE; }
    game g; game_init (&g, ai, c, two_player, winning, +1);

    if (dump) {
        render (&g, &canvas);
        int rr = btp_render_ansi_fd (&canvas, 1);
        btp_canvas_free (&canvas);
        return rr == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    btp_tty_state tty; int raw = btp_tty_enter_raw (&tty, 0) == 0;
    struct timespec prev, frame; clock_gettime (CLOCK_MONOTONIC, &prev); frame = prev;
    long frame_ns = 1000000000L / fps;
    int rendered = 0, quit = 0;
    int up_l = 0, dn_l = 0, up_r = 0, dn_r = 0;

    while (!quit) {
        char key[32];
        while (btp_read_key (0, 0, key, sizeof key) == 1) {
            if      (!strcmp (key, "ESCAPE")) quit = 1;
            else if (!strcmp (key, "CTRL_C")) quit = 1;
            else if (!strcmp (key, "p")) g.paused = !g.paused;
            else if (!strcmp (key, "ENTER") && g.over) { rng_seed (seed); game_init (&g, ai, c, two_player, winning, +1); }
            else if (!strcmp (key, "w")) { up_l = 1; dn_l = 0; }
            else if (!strcmp (key, "s")) { dn_l = 1; up_l = 0; }
            else if (!strcmp (key, "UP_ARROW")) { up_r = 1; dn_r = 0; }
            else if (!strcmp (key, "DOWN_ARROW")) { dn_r = 1; up_r = 0; }
        }
        struct timespec now; clock_gettime (CLOCK_MONOTONIC, &now);
        double dt = (now.tv_sec - prev.tv_sec) + (now.tv_nsec - prev.tv_nsec) / 1e9;
        prev = now;
        if (dt > 0.1) dt = 0.1;
        update (&g, dt, up_l, dn_l, up_r, dn_r);
        up_l = dn_l = up_r = dn_r = 0;     /* require re-press per frame */
        render (&g, &canvas);
        (void) write (1, "\033[H", 3);
        if (btp_render_ansi_fd (&canvas, 1) != 0) break;
        rendered++;
        if (frames >= 0 && rendered >= frames) break;
        frame.tv_nsec += frame_ns;
        if (frame.tv_nsec >= 1000000000L) { frame.tv_nsec -= 1000000000L; frame.tv_sec++; }
        btp_sleep_until_monotonic (frame);
    }
    if (raw) btp_tty_restore (&tty);
    btp_canvas_free (&canvas);
    return EXECUTION_SUCCESS;
}

char *termpixel_pong_doc[] = {
    "Pong built on the termpixel substrate (no Python).",
    "",
    "    termpixel_pong [--ai[=easy|medium|hard]] [--two-player] [--fps N]",
    "                   [--frames N] [--seed N] [--winning-score N]",
    "                   [--no-sound] [--dump-frame] [--selftest]",
    "",
    "Controls: left paddle w/s, right paddle Up/Down, p pause, ESC quit,",
    "ENTER restart after game over. --frames N exits after N frames (tests);",
    "--dump-frame prints one deterministic frame and exits.",
    (char *) NULL
};

struct builtin termpixel_pong_struct = {
    "termpixel_pong",
    termpixel_pong_builtin,
    BUILTIN_ENABLED,
    termpixel_pong_doc,
    "termpixel_pong [--ai[=easy|medium|hard]] [--two-player] [--frames N] [--seed N] ...",
    0
};
