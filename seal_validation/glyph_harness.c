#include <stdlib.h>
#include <stdint.h>

/* CVE-2026-86950 model: coordinate -> 64-bit fixed -> 32-bit NARROW (aa_lineto XTN
 * truncation). The coverage buffer is sized from the (wrapped) width, but the glyph
 * really spans GLYPH_SPAN pixels, so the rasterizer writes a pixel the undersized
 * buffer doesn't contain -> heap out-of-bounds write.                               */
#define SCALE 4096
#define GLYPH_SPAN 200          /* pixels the real glyph covers */

__attribute__((noinline))
int render_glyph(long coord) {
    int64_t wide = (int64_t)coord * SCALE;      /* 64-bit fixed (fcvtzs v.2d) */
    int32_t fx   = (int32_t)wide;               /* 32-bit NARROW/truncate  <-- the bug */

    uint32_t aw       = (uint32_t)(fx < 0 ? -fx : fx);
    uint32_t width_px = aw / SCALE + 1;         /* coverage width from the WRAPPED value */

    unsigned char *cov = (unsigned char *)malloc(width_px);  /* undersized when fx wrapped */
    if (!cov) return -1;

    cov[GLYPH_SPAN] = 0xFF;      /* rasterize a real-glyph pixel -> OOB when width_px <= 200 */
    return (int)fx;
}

int main(int argc, char **argv) {
    long c = (argc > 1) ? atol(argv[1]) : 0;
    return render_glyph(c);
}
