#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "png.h"

/* Silent error/warning handlers so the oracle can match exact output. */
static void silent_error(png_structp png, png_const_charp msg) {
    (void)msg;
    png_longjmp(png, 1);
}

static void silent_warning(png_structp png, png_const_charp msg) {
    (void)png;
    (void)msg;
}

/* Copy `n` palette entries into a buffer sized for the correct maximum of the
 * bit depth (1 << bit_depth). On the vulnerable/incomplete builds libpng accepts
 * n == 256 for a small bit depth, so this copy overflows. */
static void copy_palette(png_colorp pal, int n, int bit_depth) {
    int correct = 1 << bit_depth;
    png_colorp buf = (png_colorp)malloc((size_t)correct * sizeof(png_color));
    if (!buf) exit(2);
    memcpy(buf, pal, (size_t)n * sizeof(png_color));
    volatile unsigned long sink = 0;
    int i;
    for (i = 0; i < n; i++)
        sink += (unsigned char)buf[i].red + (unsigned char)buf[i].green + (unsigned char)buf[i].blue;
    (void)sink;
    free(buf);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: pnginfo FILE\n"); return 2; }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { fprintf(stderr, "open failed\n"); return 2; }

    png_structp rpng = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, silent_error, silent_warning);
    if (!rpng) return 2;
    png_infop rinfo = png_create_info_struct(rpng);
    if (!rinfo) return 2;

    if (setjmp(png_jmpbuf(rpng))) {
        png_destroy_read_struct(&rpng, &rinfo, NULL);
        fclose(fp);
        fprintf(stderr, "png error\n");
        return 1;
    }

    png_init_io(rpng, fp);
    png_read_info(rpng, rinfo);

    png_uint_32 width = png_get_image_width(rpng, rinfo);
    png_uint_32 height = png_get_image_height(rpng, rinfo);
    int bit_depth = png_get_bit_depth(rpng, rinfo);
    int color_type = png_get_color_type(rpng, rinfo);

    png_bytepp rows = (png_bytepp)malloc((size_t)height * sizeof(png_bytep));
    if (!rows) return 2;
    {
        png_uint_32 y;
        for (y = 0; y < height; y++)
            rows[y] = (png_bytep)malloc(png_get_rowbytes(rpng, rinfo));
    }
    png_read_image(rpng, rows);
    {
        png_uint_32 y;
        for (y = 0; y < height; y++) free(rows[y]);
    }
    free(rows);
    png_read_end(rpng, NULL);
    png_destroy_read_struct(&rpng, &rinfo, NULL);
    fclose(fp);

    /* Re-encode through the public png_set_PLTE API. A palette-expanding tool
     * re-sets a 256-entry palette; libpng must reject that for bit depth < 8.
     * This is CVE-2015-8472 (the incomplete fix of CVE-2015-8126). */
    int num_palette = 0;
    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        png_structp wpng = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, silent_error, silent_warning);
        if (!wpng) return 2;
        png_infop winfo = png_create_info_struct(wpng);
        if (!winfo) return 2;
        if (setjmp(png_jmpbuf(wpng))) {
            png_destroy_write_struct(&wpng, &winfo);
            fprintf(stderr, "png error\n");
            return 1;
        }
        png_set_IHDR(wpng, winfo, width, height, bit_depth, color_type, 0, 0, 0);
        png_color palette[PNG_MAX_PALETTE_LENGTH];
        int i;
        for (i = 0; i < PNG_MAX_PALETTE_LENGTH; i++) {
            palette[i].red = (png_byte)(i * 3);
            palette[i].green = (png_byte)(i * 5);
            palette[i].blue = (png_byte)(i * 7);
        }
        png_set_PLTE(wpng, winfo, palette, PNG_MAX_PALETTE_LENGTH);
        png_colorp got = NULL;
        int n = 0;
        if (png_get_PLTE(wpng, winfo, &got, &n) && got != NULL && n > 0) {
            num_palette = n;
            copy_palette(got, n, bit_depth);
        }
        png_destroy_write_struct(&wpng, &winfo);
    }

    printf("OK %u %u %d %d %d\n", width, height, bit_depth, color_type, num_palette);
    return 0;
}
