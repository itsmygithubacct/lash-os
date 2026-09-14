/* SPDX-License-Identifier: MIT */
/* Optional GBM/EGL/GLES2 renderer. These are public Linux ABI declarations,
   kept here so an SDK without graphics development headers can build gpu.
   No driver is loaded until a rendering command or DMA-BUF is requested. */
#ifndef BASHOS_GPU_NATIVE_H
#define BASHOS_GPU_NATIVE_H

#include <dlfcn.h>

typedef struct {
    void *gbm_lib, *egl_lib, *gl_lib, *device, *bo, *display, *context, *image;
    int fd, width, height, input_valid;
    unsigned texture, input, framebuffer, program, copy_program;
    char renderer[160], error[512];
    void *(*gbm_create_device)(int);
    void (*gbm_device_destroy)(void *);
    void *(*gbm_bo_create)(void *, uint32_t, uint32_t, uint32_t, uint32_t);
    void (*gbm_bo_destroy)(void *);
    int (*gbm_bo_get_fd)(void *);
    uint32_t (*gbm_bo_get_stride)(void *);
    uint32_t (*gbm_bo_get_offset)(void *, int);
    uint64_t (*gbm_bo_get_modifier)(void *);
    void *(*eglGetDisplay)(void *);
    void *(*eglGetPlatformDisplayEXT)(unsigned, void *, const int *);
    void *(*eglGetProcAddress)(const char *);
    unsigned (*eglInitialize)(void *, int *, int *);
    unsigned (*eglBindAPI)(unsigned);
    unsigned (*eglChooseConfig)(void *, const int *, void **, int, int *);
    void *(*eglCreateContext)(void *, void *, void *, const int *);
    unsigned (*eglMakeCurrent)(void *, void *, void *, void *);
    unsigned (*eglDestroyContext)(void *, void *);
    unsigned (*eglTerminate)(void *);
    void *(*eglCreateImageKHR)(void *, void *, unsigned, void *, const int *);
    unsigned (*eglDestroyImageKHR)(void *, void *);
    void (*glEGLImageTargetTexture2DOES)(unsigned, void *);
    void (*glGenTextures)(int, unsigned *);
    void (*glDeleteTextures)(int, const unsigned *);
    void (*glBindTexture)(unsigned, unsigned);
    void (*glTexParameteri)(unsigned, unsigned, int);
    void (*glTexImage2D)(unsigned, int, int, int, int, int, unsigned, unsigned, const void *);
    void (*glGenFramebuffers)(int, unsigned *);
    void (*glDeleteFramebuffers)(int, const unsigned *);
    void (*glBindFramebuffer)(unsigned, unsigned);
    void (*glFramebufferTexture2D)(unsigned, unsigned, unsigned, unsigned, int);
    unsigned (*glCheckFramebufferStatus)(unsigned);
    unsigned (*glCreateShader)(unsigned);
    void (*glShaderSource)(unsigned, int, const char *const *, const int *);
    void (*glCompileShader)(unsigned);
    void (*glGetShaderiv)(unsigned, unsigned, int *);
    void (*glGetShaderInfoLog)(unsigned, int, int *, char *);
    void (*glDeleteShader)(unsigned);
    unsigned (*glCreateProgram)(void);
    void (*glAttachShader)(unsigned, unsigned);
    void (*glBindAttribLocation)(unsigned, unsigned, const char *);
    void (*glLinkProgram)(unsigned);
    void (*glGetProgramiv)(unsigned, unsigned, int *);
    void (*glGetProgramInfoLog)(unsigned, int, int *, char *);
    void (*glDeleteProgram)(unsigned);
    void (*glUseProgram)(unsigned);
    int (*glGetUniformLocation)(unsigned, const char *);
    void (*glUniform1f)(int, float);
    void (*glUniform2f)(int, float, float);
    void (*glUniform1i)(int, int);
    void (*glViewport)(int, int, int, int);
    void (*glActiveTexture)(unsigned);
    void (*glEnableVertexAttribArray)(unsigned);
    void (*glVertexAttribPointer)(unsigned, int, unsigned, unsigned char, int, const void *);
    void (*glDrawArrays)(unsigned, int, int);
    void (*glReadPixels)(int, int, int, int, unsigned, unsigned, void *);
    void (*glFinish)(void);
    unsigned (*glGetError)(void);
    const unsigned char *(*glGetString)(unsigned);
} bg_native;

enum {
    BG_TEXTURE = 0x0de1, BG_RGBA = 0x1908, BG_BYTE = 0x1401,
    BG_FBO = 0x8d40, BG_COLOR = 0x8ce0, BG_COMPLETE = 0x8cd5,
    BG_XRGB = 0x34325258, BG_EGL_NONE = 0x3038
};

static void bg_native_close(bg_native *n)
{
    if (n->context && n->eglMakeCurrent) {
        n->eglMakeCurrent(n->display, NULL, NULL, n->context);
        if (n->glDeleteProgram) {
            if (n->program) n->glDeleteProgram(n->program);
            if (n->copy_program) n->glDeleteProgram(n->copy_program);
        }
        if (n->glDeleteFramebuffers && n->framebuffer)
            n->glDeleteFramebuffers(1, &n->framebuffer);
        if (n->glDeleteTextures) {
            if (n->texture) n->glDeleteTextures(1, &n->texture);
            if (n->input) n->glDeleteTextures(1, &n->input);
        }
        if (n->image && n->eglDestroyImageKHR) n->eglDestroyImageKHR(n->display, n->image);
        n->eglMakeCurrent(n->display, NULL, NULL, NULL);
        n->eglDestroyContext(n->display, n->context);
    }
    if (n->display && n->eglTerminate) n->eglTerminate(n->display);
    if (n->bo && n->gbm_bo_destroy) n->gbm_bo_destroy(n->bo);
    if (n->device && n->gbm_device_destroy) n->gbm_device_destroy(n->device);
    if (n->fd >= 0) close(n->fd);
    if (n->gl_lib) dlclose(n->gl_lib);
    if (n->egl_lib) dlclose(n->egl_lib);
    if (n->gbm_lib) dlclose(n->gbm_lib);
    memset(n, 0, sizeof(*n));
    n->fd = -1;
}

static unsigned bg_program(bg_native *n, const char *fragment)
{
    const char *vertex = "attribute vec2 position; varying vec2 uv;"
        "void main(){uv=vec2((position.x+1.0)*0.5,(1.0-position.y)*0.5);"
        "gl_Position=vec4(position,0.0,1.0);}";
    unsigned shaders[2] = {0}, program = 0;
    const char *sources[2] = {vertex, fragment};
    for (int i = 0; i < 2; i++) {
        shaders[i] = n->glCreateShader(i ? 0x8b30 : 0x8b31);
        n->glShaderSource(shaders[i], 1, &sources[i], NULL);
        n->glCompileShader(shaders[i]);
        int ok = 0;
        n->glGetShaderiv(shaders[i], 0x8b81, &ok);
        if (!ok) {
            n->glGetShaderInfoLog(shaders[i], sizeof(n->error), NULL, n->error);
            goto done;
        }
    }
    program = n->glCreateProgram();
    n->glAttachShader(program, shaders[0]); n->glAttachShader(program, shaders[1]);
    n->glBindAttribLocation(program, 0, "position");
    n->glLinkProgram(program);
    int ok = 0;
    n->glGetProgramiv(program, 0x8b82, &ok);
    if (!ok) {
        n->glGetProgramInfoLog(program, sizeof(n->error), NULL, n->error);
        n->glDeleteProgram(program); program = 0;
    }
done:
    for (int i = 0; i < 2; i++) if (shaders[i]) n->glDeleteShader(shaders[i]);
    return program;
}

static int bg_native_open(bg_native *n, const char *path, int width, int height)
{
    const char *reason = "graphics libraries unavailable";
    const char *lib;
    memset(n, 0, sizeof(*n)); n->fd = -1;
#if defined(__ELF__)
    /* Static libc cannot safely load arbitrary Mesa drivers (including their
       TLS and libc dependencies). Keep the software canvas usable there. */
    extern const char _DYNAMIC[] __attribute__((weak));
    if (!_DYNAMIC) { reason = "GPU drivers require a dynamically linked Bash"; goto fail; }
#endif
    lib = getenv("BASHOS_GPU_GBM_LIB");
    n->gbm_lib = dlopen(lib ? lib : "libgbm.so.1", RTLD_NOW | RTLD_LOCAL);
    lib = getenv("BASHOS_GPU_EGL_LIB");
    n->egl_lib = dlopen(lib ? lib : "libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    lib = getenv("BASHOS_GPU_GLES_LIB");
    n->gl_lib = dlopen(lib ? lib : "libGLESv2.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!n->gbm_lib || !n->egl_lib || !n->gl_lib) goto fail;
#define BG_SYM(handle, name) do { \
    void *symbol = dlsym(n->handle, #name); \
    if (!symbol) { reason = "missing graphics entry point: " #name; goto fail; } \
    memcpy(&n->name, &symbol, sizeof(symbol)); \
} while (0)
    BG_SYM(gbm_lib, gbm_create_device); BG_SYM(gbm_lib, gbm_device_destroy);
    BG_SYM(gbm_lib, gbm_bo_create); BG_SYM(gbm_lib, gbm_bo_destroy);
    BG_SYM(gbm_lib, gbm_bo_get_fd); BG_SYM(gbm_lib, gbm_bo_get_stride);
    BG_SYM(gbm_lib, gbm_bo_get_offset); BG_SYM(gbm_lib, gbm_bo_get_modifier);
    BG_SYM(egl_lib, eglGetDisplay); BG_SYM(egl_lib, eglGetProcAddress);
    BG_SYM(egl_lib, eglInitialize); BG_SYM(egl_lib, eglBindAPI);
    BG_SYM(egl_lib, eglChooseConfig); BG_SYM(egl_lib, eglCreateContext);
    BG_SYM(egl_lib, eglMakeCurrent); BG_SYM(egl_lib, eglDestroyContext);
    BG_SYM(egl_lib, eglTerminate);
    BG_SYM(gl_lib, glGenTextures); BG_SYM(gl_lib, glDeleteTextures);
    BG_SYM(gl_lib, glBindTexture); BG_SYM(gl_lib, glTexParameteri);
    BG_SYM(gl_lib, glTexImage2D); BG_SYM(gl_lib, glGenFramebuffers);
    BG_SYM(gl_lib, glDeleteFramebuffers); BG_SYM(gl_lib, glBindFramebuffer);
    BG_SYM(gl_lib, glFramebufferTexture2D); BG_SYM(gl_lib, glCheckFramebufferStatus);
    BG_SYM(gl_lib, glCreateShader); BG_SYM(gl_lib, glShaderSource);
    BG_SYM(gl_lib, glCompileShader); BG_SYM(gl_lib, glGetShaderiv);
    BG_SYM(gl_lib, glGetShaderInfoLog); BG_SYM(gl_lib, glDeleteShader);
    BG_SYM(gl_lib, glCreateProgram); BG_SYM(gl_lib, glAttachShader);
    BG_SYM(gl_lib, glBindAttribLocation); BG_SYM(gl_lib, glLinkProgram);
    BG_SYM(gl_lib, glGetProgramiv); BG_SYM(gl_lib, glGetProgramInfoLog);
    BG_SYM(gl_lib, glDeleteProgram); BG_SYM(gl_lib, glUseProgram);
    BG_SYM(gl_lib, glGetUniformLocation); BG_SYM(gl_lib, glUniform1f);
    BG_SYM(gl_lib, glUniform2f); BG_SYM(gl_lib, glUniform1i);
    BG_SYM(gl_lib, glViewport); BG_SYM(gl_lib, glActiveTexture);
    BG_SYM(gl_lib, glEnableVertexAttribArray); BG_SYM(gl_lib, glVertexAttribPointer);
    BG_SYM(gl_lib, glDrawArrays); BG_SYM(gl_lib, glReadPixels);
    BG_SYM(gl_lib, glFinish); BG_SYM(gl_lib, glGetError); BG_SYM(gl_lib, glGetString);
#undef BG_SYM
#define BG_PROC(name) do { \
    void *symbol = n->eglGetProcAddress(#name); \
    if (!symbol) { reason = "missing EGL extension: " #name; goto fail; } \
    memcpy(&n->name, &symbol, sizeof(symbol)); \
} while (0)
    BG_PROC(eglGetPlatformDisplayEXT); BG_PROC(eglCreateImageKHR);
    BG_PROC(eglDestroyImageKHR); BG_PROC(glEGLImageTargetTexture2DOES);
#undef BG_PROC
    reason = "cannot open render node";
    n->fd = open(path, O_RDWR | O_CLOEXEC);
    if (n->fd < 0) goto fail;
    reason = "cannot initialize GBM device";
    n->device = n->gbm_create_device(n->fd);
    if (!n->device) goto fail;
    reason = "cannot initialize EGL on render node";
    n->display = n->eglGetPlatformDisplayEXT(0x31d7, n->device, NULL);
    if (!n->display || !n->eglInitialize(n->display, NULL, NULL)) goto fail;
    reason = "surfaceless GLES2 context unavailable";
    void *config = NULL;
    int count = 0, attrs[] = {0x3040, 4, 0x3033, 0, BG_EGL_NONE};
    int context_attrs[] = {0x3098, 2, BG_EGL_NONE};
    if (!n->eglBindAPI(0x30a0) ||
        !n->eglChooseConfig(n->display, attrs, &config, 1, &count) || !count) goto fail;
    n->context = n->eglCreateContext(n->display, config, NULL, context_attrs);
    if (!n->context || !n->eglMakeCurrent(n->display, NULL, NULL, n->context)) goto fail;
    const unsigned char *renderer = n->glGetString(0x1f01);
    snprintf(n->renderer, sizeof(n->renderer), "%s", renderer ? (const char *)renderer : "unknown");
    reason = "linear renderable buffer unavailable";
    n->bo = n->gbm_bo_create(n->device, width, height, BG_XRGB, (1u << 2) | (1u << 4));
    if (!n->bo) goto fail;
    int fd = n->gbm_bo_get_fd(n->bo);
    if (fd < 0) goto fail;
    int image_attrs[] = {0x3057, width, 0x3056, height, 0x3271, BG_XRGB,
        0x3272, fd, 0x3273, (int)n->gbm_bo_get_offset(n->bo, 0),
        0x3274, (int)n->gbm_bo_get_stride(n->bo), BG_EGL_NONE};
    n->image = n->eglCreateImageKHR(n->display, NULL, 0x3270, NULL, image_attrs);
    close(fd);
    reason = "EGL cannot import render buffer";
    if (!n->image) goto fail;
    n->glGenTextures(1, &n->texture); n->glBindTexture(BG_TEXTURE, n->texture);
    n->glTexParameteri(BG_TEXTURE, 0x2801, 0x2600);
    n->glTexParameteri(BG_TEXTURE, 0x2800, 0x2600);
    n->glEGLImageTargetTexture2DOES(BG_TEXTURE, n->image);
    n->glGenFramebuffers(1, &n->framebuffer); n->glBindFramebuffer(BG_FBO, n->framebuffer);
    n->glFramebufferTexture2D(BG_FBO, BG_COLOR, BG_TEXTURE, n->texture, 0);
    reason = "render buffer is not framebuffer-complete";
    if (n->glCheckFramebufferStatus(BG_FBO) != BG_COMPLETE) goto fail;
    n->glGenTextures(1, &n->input); n->glBindTexture(BG_TEXTURE, n->input);
    n->glTexParameteri(BG_TEXTURE, 0x2801, 0x2600);
    n->glTexParameteri(BG_TEXTURE, 0x2800, 0x2600);
    n->glTexParameteri(BG_TEXTURE, 0x2802, 0x812f);
    n->glTexParameteri(BG_TEXTURE, 0x2803, 0x812f);
    n->copy_program = bg_program(n, "precision mediump float; varying vec2 uv;"
        "uniform sampler2D canvas; void main(){gl_FragColor=texture2D(canvas,uv);}");
    reason = "cannot compile canvas shader";
    if (!n->copy_program || n->glGetError()) goto fail;
    n->width = width; n->height = height;
    return 0;
fail:
    bg_native_close(n);
    snprintf(n->error, sizeof(n->error), "%s", reason);
    return -1;
}

static int bg_native_draw(bg_native *n, const unsigned char *rgba, float time, int custom)
{
    if (!n->eglMakeCurrent(n->display, NULL, NULL, n->context)) { errno = EIO; return -1; }
    n->glBindFramebuffer(BG_FBO, n->framebuffer);
    n->glViewport(0, 0, n->width, n->height);
    n->glActiveTexture(0x84c0);
    n->glBindTexture(BG_TEXTURE, n->input);
    if (rgba) n->glTexImage2D(BG_TEXTURE, 0, BG_RGBA, n->width, n->height, 0, BG_RGBA, BG_BYTE, rgba);
    unsigned program = custom ? n->program : n->copy_program;
    n->glUseProgram(program);
    n->glUniform1i(n->glGetUniformLocation(program, "canvas"), 0);
    n->glUniform1f(n->glGetUniformLocation(program, "time"), time);
    n->glUniform2f(n->glGetUniformLocation(program, "resolution"), n->width, n->height);
    const float vertices[] = {-1,-1, 1,-1, -1,1, 1,1};
    n->glEnableVertexAttribArray(0);
    n->glVertexAttribPointer(0, 2, 0x1406, 0, 0, vertices);
    n->glDrawArrays(5, 0, 4);
    n->glFinish();
    if (n->glGetError()) { n->input_valid = 0; errno = EIO; return -1; }
    n->input_valid = 1;
    return 0;
}

static int bg_native_read(bg_native *n, sr_canvas *canvas, unsigned char *rgba)
{
    if (!n->eglMakeCurrent(n->display, NULL, NULL, n->context)) { errno = EIO; return -1; }
    n->glBindFramebuffer(BG_FBO, n->framebuffer);
    n->glReadPixels(0, 0, n->width, n->height, BG_RGBA, BG_BYTE, rgba);
    if (n->glGetError()) { errno = EIO; return -1; }
    for (int y = 0; y < n->height; y++)
        for (int x = 0; x < n->width; x++) {
            unsigned char *p = rgba + ((size_t)(n->height - 1 - y) * n->width + x) * 4;
            canvas->px[(size_t)y * n->width + x] = 0xff000000u | (p[0] << 16) | (p[1] << 8) | p[2];
        }
    return 0;
}
#endif
