#include <CoreGraphics/CoreGraphics.h>
/* Drive CoreGraphics' anti-aliased path fill, which runs the aa_* scanline
 * rasterizer (aa_merge_scanline_edge et al.) — the code we want to snapshot. */
int main(void) {
    size_t w = 128, h = 128;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, 0, cs, kCGImageAlphaNone);
    if (!ctx) return 2;
    CGContextSetShouldAntialias(ctx, true);
    CGContextSetGrayFillColor(ctx, 1.0, 1.0);
    for (int i = 0; i < 4; i++) {                 /* a few diagonal triangles -> scanline edge merging */
        CGContextBeginPath(ctx);
        CGContextMoveToPoint(ctx, 3 + i, 3);
        CGContextAddLineToPoint(ctx, 120, 11 + i);
        CGContextAddLineToPoint(ctx, 40 + i, 118);
        CGContextClosePath(ctx);
        CGContextFillPath(ctx);
    }
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
    return 0;
}
