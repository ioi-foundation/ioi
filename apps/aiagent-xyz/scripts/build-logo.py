#!/usr/bin/env python3
"""Regenerates public/animated-logo.svg (and variants) — the logo is BUILT, never hand-edited.

Base artwork: git show 6b4ab193e^:apps/aiagent-xyz/public/animated-logo.svg > base.svg
Font: internetofintelligence-com/public/fonts/IOI.ttf (IOI Display, unicase).
Deps: pip install fonttools. Run: python3 build-logo.py (paths at top).
NOTE (2026-08-25): the SHIPPED animated-logo.svg has the marks placement BAKED
INTO ITS COORDINATES (owner transform x0.7 +91/+20 flattened by
scripts/flatten-logo-transform.py). This script still emits the wrapper form;
a regeneration must be followed by that flatten step to reproduce the shipped
file.
"""
import re
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen
from fontTools.misc.transform import Transform

SP = "/tmp/claude-1000/-home-heathledger-Documents-ioi-repos-ioi/a8561696-675b-4d4a-a964-c2732ce6df99/scratchpad"
FONT = "/home/heathledger/Documents/ioi/repos/internetofintelligence-com/public/fonts/IOI.ttf"

# geometry: A's measured extents with a 1.2-unit optical trim per end on the flat-topped I
ITOP, IBOT = 77.98 + 1.2, 213.78 - 1.2
IX, IW = 283.6, 30.0
CX = IX + IW/2
NODE_Y = ITOP + 8.0
WIRE_BOT = IBOT - 8.0
H = IBOT - ITOP
RXC, CYC, SC = 313.6, 145.88, 0.765    # marks wrapper: 76.5% about the pair's right edge
BASELINE, OVERSHOOT = 171.9, 1.5       # marks stand on the wordmark baseline (+1.5u for rounded feet)
TY = (BASELINE + OVERSHOOT) - (CYC + SC*67.9)   # vertical drop to seat the marks
INK = "#00234d"                        # wordmark ink = marks' darkest navy
KERN = {("a","g"): -10, ("n","t"): -14}

def fold_shapes(variant):
    teal = f'<rect x="{IX}" y="{ITOP}" width="{IW}" height="{H:.2f}" fill="url(#i-mark-grad)"/>'
    if variant == "apex":
        # crease 12->22 (bracket winner g1c1); shading direction matches the A's
        # apex plane: darkest at the tip, lightening toward the crease
        navy = f'<polygon points="{IX},{ITOP} {IX+IW},{ITOP} {IX+IW},{ITOP+12} {IX},{ITOP+22}" fill="url(#i-fold-grad)"/>'
    elif variant == "foot":
        navy = f'<polygon points="{IX},{IBOT-12:.2f} {IX+IW},{IBOT-26:.2f} {IX+IW},{IBOT:.2f} {IX},{IBOT:.2f}" fill="url(#i-fold-grad)"/>'
    else:  # side
        navy = f'<rect x="{IX+IW-8}" y="{ITOP}" width="8" height="{H:.2f}" fill="url(#i-fold-grad)"/>'
    return teal + "\n    " + navy

def fold_grad(variant):
    if variant == "apex":
        return f'<linearGradient id="i-fold-grad" x1="{CX}" y1="{ITOP}" x2="{CX}" y2="{ITOP+22}" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#00234d"/><stop offset="1" stop-color="#044994"/></linearGradient>'
    if variant == "foot":
        return f'<linearGradient id="i-fold-grad" x1="{CX}" y1="{IBOT-26}" x2="{CX}" y2="{IBOT}" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#00234d"/><stop offset="1" stop-color="#1160a8"/></linearGradient>'
    return f'<linearGradient id="i-fold-grad" x1="{IX+IW-8}" y1="{ITOP}" x2="{IX+IW}" y2="{IBOT}" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#1160a8"/><stop offset="1" stop-color="#00234d"/></linearGradient>'

def build(variant, out):
    svg = open(f"{SP}/base.svg").read()

    stops = re.search(r'<radialGradient id="New_Gradient_Swatch_1"[^>]*>(.*?)</radialGradient>', svg, re.S).group(1)
    stops = "\n".join(l for l in stops.splitlines() if "<stop" in l)
    def breathe(v): return f"{v:.2f};{v-7:.2f};{v:.2f};{v+7:.2f};{v:.2f}"

    defs_block = f'''<radialGradient id="i-node-grad" cx="{CX}" cy="{NODE_Y}" fx="{CX}" fy="{NODE_Y}" r="5.84729" gradientUnits="userSpaceOnUse">
{stops}
    </radialGradient>
    <linearGradient id="i-mark-grad" x1="{IX}" y1="{ITOP}" x2="{IX+IW}" y2="{IBOT}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#2fba82"/>
      <stop offset=".45" stop-color="#0ba8b4"/>
      <stop offset=".78" stop-color="#017db9"/>
      <stop offset="1" stop-color="#00408c"/>
      <animate attributeName="y1" values="{breathe(ITOP)}" dur="8s" repeatCount="indefinite" calcMode="spline" keySplines="0.4 0 0.6 1;0.4 0 0.6 1;0.4 0 0.6 1;0.4 0 0.6 1"/>
      <animate attributeName="y2" values="{breathe(IBOT)}" dur="8s" repeatCount="indefinite" calcMode="spline" keySplines="0.4 0 0.6 1;0.4 0 0.6 1;0.4 0 0.6 1;0.4 0 0.6 1"/>
    </linearGradient>
    {fold_grad(variant)}
    <clipPath id="i-mark-clip">
      <rect x="{IX}" y="{ITOP}" width="{IW}" height="{H:.2f}" rx="14"/>
    </clipPath>
    <mask id="wire-mask-1" maskUnits="userSpaceOnUse" x="253" y="60" width="120" height="200">
      <path fill="none" stroke="white" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" pathLength="1" stroke-dasharray="1" stroke-dashoffset="1" d="M{CX},{NODE_Y} L{CX},{WIRE_BOT}">
        <animate attributeName="stroke-dashoffset" values="1;1;0;0;0" keyTimes="0;0.05;0.40;0.72;1" dur="10s" begin="0s" repeatCount="indefinite" calcMode="spline" keySplines="0 0 1 1; 0.25 0.1 0.25 1; 0 0 1 1; 0 0 1 1"/>
      </path>
    </mask>
    '''
    i = svg.find('<!-- Wire 2 mask'); assert i > 0
    svg = svg[:i] + defs_block + svg[i:]

    static_block = f'''
  <g clip-path="url(#i-mark-clip)">
    {fold_shapes(variant)}
  </g>'''
    m = re.search(r'(<path class="st8"[^>]*/>\s*</g>\s*</g>)', svg, re.S)
    svg = svg[:m.end(1)] + static_block + svg[m.end(1):]

    node_block = f'''<g class="node-anim" style="--d: 0s; transform-origin: {CX}px {NODE_Y}px;">
        <circle fill="url(#i-node-grad)" cx="{CX}" cy="{NODE_Y}" r="5.84729"/>
      </g>
      <circle class="node-ping" style="--d: 0s;" cx="{CX}" cy="{NODE_Y}" r="5.847"/>
      <circle class="node-ping-2" style="--d: 0s;" cx="{CX}" cy="{NODE_Y}" r="5.847"/>
      '''
    i = svg.find('<g class="node-anim" style="--d: 2s')
    svg = svg[:i] + node_block + svg[i:]

    # line and terminal match the A's connection grammar, both measured from
    # wire 2's st6 shape: line width 1.25; hollow ring outer r 2.98, inner 1.47
    RING_Y = IBOT - 8.0
    R_MID, R_W = 2.225, 1.51
    LW = 1.25
    wire_block = f'''<g class="wire-anim" style="--d: 0s;" mask="url(#wire-mask-1)">
        <rect class="st6" x="{CX-LW/2}" y="{NODE_Y}" width="{LW}" height="{RING_Y - 2.98 - NODE_Y:.2f}" rx="{LW/2}"/>
        <circle cx="{CX}" cy="{RING_Y:.2f}" r="{R_MID}" fill="none" stroke="#fefefc" stroke-width="{R_W}"/>
      </g>
      '''
    i = svg.find('<g class="wire-anim" style="--d: 2s')
    svg = svg[:i] + wire_block + svg[i:]

    # wordmark: AGENT, cap 52, hand-kerned, navy ink
    f = TTFont(FONT)
    cmap = f.getBestCmap(); glyphset = f.getGlyphSet(); hmtx = f['hmtx']
    T=52.0; S=T/700.0; TRACK=10; BASE = BASELINE   # letters set directly on the shared baseline
    text = "agent"
    glyphs = [cmap[ord(c)] for c in text]
    bp0 = BoundsPen(glyphset); glyphset[glyphs[0]].draw(bp0)
    first_xmin = bp0.bounds[0]
    X0 = IX + IW + 42 - 10   # -10: owner's reading-gap tightening (f2894f7d8)
    pen_x = 0; new_paths = []
    for j,g in enumerate(glyphs):
        t = Transform(S,0,0,-S, X0 + S*(pen_x-first_xmin), BASE)
        sp = SVGPathPen(glyphset, ntos=lambda v: f"{v:.2f}")
        glyphset[g].draw(TransformPen(sp, t))
        new_paths.append(f'<path class="st1" d="{sp.getCommands()}"/>')
        if j < len(glyphs)-1:
            pen_x += hmtx[g][0] + TRACK + KERN.get((text[j], text[j+1]), 0)
    bpl = BoundsPen(glyphset); glyphset[glyphs[-1]].draw(bpl)
    right = X0 + S*(pen_x + bpl.bounds[2] - first_xmin)

    olds = re.findall(r'<path class="st1" d="[^"]+"/>', svg)
    assert len(olds) == 7
    svg = svg.replace(olds[0], "\n        ".join(new_paths), 1)
    for o in olds[1:]:
        svg = svg.replace(o, "", 1)
    svg = svg.replace(".st1 {\n        fill: #18222e;\n      }", f".st1 {{\n        fill: {INK};\n      }}")
    assert INK in svg, "ink swap failed"

    # reduced-motion guard (CSS animations; decorative layers rest at opacity 0)
    svg = svg.replace("]]>", """@media (prefers-reduced-motion: reduce) {
        .node-anim, .node-ping, .node-ping-2, .wire-anim { animation: none !important; }
        .wire-anim { display: none; }
      }
      ]]>""", 1)

    # marks wrapper: 76.5%, seated on the wordmark baseline (one typeset line)
    i_defs = svg.find('</defs>') + len('</defs>')
    j = svg.find('<path class="st1"')
    k = svg.rfind('<g>', 0, svg.rfind('<g>', 0, j))
    # Marks placement is the owner's hand-tuned transform (2026-08-25): scale
    # 0.7 about the base-art origin, then +91/+20 — marks at ~1.83x the
    # wordmark cap, feet grazing the shared baseline.
    svg = (svg[:i_defs]
        + '\n<g transform="translate(91 20) scale(0.7)">'
        + svg[i_defs:k] + '</g>\n' + svg[k:])

    # viewBox refit: marks bbox under the fixed transform + margins
    x0 = round(0.7*109.48 + 91 - 6.5, 1)
    y0 = round(0.7*77.98 + 20 - 16, 1)
    h = round(BASELINE + OVERSHOOT + 16 - y0, 1)
    w = round(right + 23 - x0, 1)
    svg = re.sub(r'viewBox="[\d. ]+"', f'viewBox="{x0} {y0} {w} {h}"', svg, count=1)
    svg = re.sub(r'width="\d+" height="\d+"', f'width="{w}" height="{h}"', svg, count=1)
    open(out, "w").write(svg)
    return w, h, right

if __name__ == "__main__":
    for v in ("apex", "foot", "side"):
        w,h,r = build(v, f"{SP}/fold-{v}.svg")
        print(f"{v}: viewBox {w}x{h}, lettering ends {r:.1f}")


def splice_letters(generated_svg, shipped_svg):
    """Carry the shipped wordmark outlines into a regenerated SVG verbatim.

    The letterforms in the shipped animated-logo.svg are the owner's hand-opened
    pass (commit f2894f7d8) and are wider than this script's from-scratch IOI
    Display setting. To regenerate marks without losing them, build() the new
    SVG, then swap its letter paths for the shipped ones:

        new = splice_letters(open(out).read(), open(shipped).read())
    """
    import re as _re
    shipped = _re.findall(r'<path class="st1" d="[^"]+"/>', shipped_svg)
    generated = _re.findall(r'<path class="st1" d="[^"]+"/>', generated_svg)
    out = generated_svg.replace(generated[0], "\n      ".join(shipped), 1)
    for o in generated[1:]:
        out = out.replace(o, "", 1)
    return out
