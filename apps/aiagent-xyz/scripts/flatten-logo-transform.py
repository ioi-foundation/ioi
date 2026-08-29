"""Bake the marks' placement transform into the geometry itself.

The shipped lockup carried the owner's placement as a wrapper transform
(translate(91 20) scale(0.7)) over base-art coordinates. This script applies
that affine to every coordinate the wrapper governed — path data, polygon
points, circles, rects, userSpaceOnUse gradients and masks, clip rects,
animation transform-origins, SMIL value lists — and to the CSS lengths that
previously inherited the scale (ping stroke widths, glow drop-shadow radii),
then removes the wrapper. The letters group sits outside the wrapper and is
untouched. Visual output must be pixel-identical; verify before committing.
"""
import re, sys
# dependency: pip install svgpathtools
from svgpathtools import parse_path

S, TX, TY = 0.7, 91.0, 20.0
fx = lambda v: S * v + TX
fy = lambda v: S * v + TY
fs = lambda v: S * v
def r2(v): return f"{v:.2f}".rstrip('0').rstrip('.')

def flatten(svg):
    # split: everything inside the wrapper is marks; letters group follows it
    m = re.search(r'<g transform="translate\(91 20\) scale\(0\.7\)">', svg)
    assert m, "wrapper not found"
    open_i = m.start()
    # find the wrapper's matching close: scan group depth
    i, depth = m.end(), 1
    while depth:
        nxt_open = svg.find('<g', i)
        nxt_close = svg.find('</g>', i)
        if nxt_open != -1 and nxt_open < nxt_close:
            depth += 1; i = nxt_open + 2
        else:
            depth -= 1; i = nxt_close + 4
    close_i = i
    head, marks, tail = svg[:open_i], svg[m.end():close_i-4], svg[close_i:]

    def path_d(d):
        p = parse_path(d)
        p = p.scaled(S).translated(complex(TX, TY))
        return p.d()

    def do_geometry(s):
        s = re.sub(r'\bd="([^"]+)"', lambda g: f'd="{path_d(g.group(1))}"', s)
        def poly(g):
            import re as _re
            nums = [float(v) for v in _re.split(r'[\s,]+', g.group(1).strip())]
            out = [r2(fx(v)) if i % 2 == 0 else r2(fy(v)) for i, v in enumerate(nums)]
            return f'points="{" ".join(out)}"'
        s = re.sub(r'points="([^"]+)"', poly, s)
        for attr, f in (("cx", fx), ("cy", fy), ("fx", fx), ("fy", fy), ("x1", fx), ("x2", fx), ("y1", fy), ("y2", fy), ("x", fx), ("y", fy), ("r", fs), ("rx", fs), ("width", fs), ("height", fs), ("stroke-width", fs)):
            s = re.sub(rf'\b{attr}="([\d.-]+)"', lambda g, f=f: f'{attr}="{r2(f(float(g.group(1))))}"', s)
        s = re.sub(r'transform-origin: ([\d.]+)px ([\d.]+)px',
                   lambda g: f'transform-origin: {r2(fx(float(g.group(1))))}px {r2(fy(float(g.group(2))))}px', s)
        return s

    marks = do_geometry(marks)

    # defs are userSpaceOnUse and referenced only by marks; flatten their
    # geometry + the gradient-breathing SMIL value lists (y-axis values)
    def defs_block(g):
        block = do_geometry(g.group(0))
        def vals(gm):
            nums = [r2(fy(float(v))) for v in gm.group(2).split(';')]
            return f'attributeName="{gm.group(1)}" values="{";".join(nums)}"'
        block = re.sub(r'attributeName="(y1|y2)" values="([\d.;-]+)"', vals, block)
        return block
    head = re.sub(r'<defs>.*?</defs>', defs_block, head, count=1, flags=re.S)

    # CSS lengths that inherited the wrapper scale
    def css(g):
        block = g.group(0)
        block = re.sub(r'stroke-width: ([\d.]+);', lambda m2: f'stroke-width: {r2(fs(float(m2.group(1))))};', block)
        block = re.sub(r'drop-shadow\(0 0 ([\d.]+)px', lambda m2: f'drop-shadow(0 0 {r2(fs(float(m2.group(1))))}px', block)
        return block
    head = re.sub(r'<style>.*?</style>', css, head, count=1, flags=re.S)

    new_comment = ('<!-- Marks geometry carries the owner\'s placement (2026-08-25) baked into\n'
                   '     the coordinates themselves: base art x0.7 then +91/+20. There is no\n'
                   '     wrapper transform; what you see is what the numbers say. -->\n<g>')
    head = re.sub(r'<!-- Marks placement is the owner\'s hand-tuned transform.*?-->\n', '', head, flags=re.S)
    return head + new_comment + marks + '</g>\n' + tail

APP = "/tmp/claude-1000/-home-heathledger-Documents-ioi-repos-ioi/33e55c56-543e-4e7d-9cc0-b5da6d1efcac/scratchpad/wt-aiagent/apps/aiagent-xyz"
svg = open(f"{APP}/public/animated-logo.svg").read()
out = flatten(svg)
open(f"{APP}/public/animated-logo.svg", "w").write(out)
print("flattened;", len(svg), "->", len(out), "bytes")
