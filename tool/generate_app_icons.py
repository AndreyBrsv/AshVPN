"""Render Ashapp's SVG primitives into checked-in desktop icons.

Development-only dependency: pip install -r tool/icon-requirements.txt
No font, network service or external artwork is used. Release builds consume the
committed assets and do not need Pillow. Keep the small SVG vocabulary explicit.
"""
import argparse
import io
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageColor, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SVG = ROOT / 'branding/ashapp.svg'
SIZES = (16, 32, 64, 128, 256, 512, 1024)


def render():
    source = ET.parse(SVG).getroot()
    if source.attrib.get('viewBox') != '0 0 1024 1024':
        raise ValueError('Expected the 1024-square icon canvas.')
    scale = 2
    extent = 1024 * scale
    image = Image.new('RGBA', (extent, extent))
    namespace = {'s': 'http://www.w3.org/2000/svg'}
    gradients = {item.attrib['id']: item for item in source.findall('s:defs/s:linearGradient', namespace)}
    filters = {item.attrib['id']: item for item in source.findall('s:defs/s:filter', namespace)}

    def gradient_fill(reference, bounds):
        if not reference.startswith('url(#') or not reference.endswith(')'):
            raise ValueError('Unsupported SVG gradient reference.')
        definition = gradients[reference[5:-1]]
        if definition.attrib.get('x1', '0') != definition.attrib.get('x2', '0'):
            raise ValueError('Only vertical gradients are supported.')
        stops = [(float(stop.attrib['offset']), ImageColor.getrgb(stop.attrib['stop-color']))
                 for stop in definition]
        if len(stops) < 2 or any(a[0] >= b[0] for a, b in zip(stops, stops[1:])):
            raise ValueError('Expected ordered gradient stops.')
        _, y, _, height = bounds
        start, end = [float(definition.attrib.get(key, default)) for key, default in (('y1', '0'), ('y2', '1'))]
        if definition.attrib.get('gradientUnits') == 'userSpaceOnUse':
            start, end = start * scale, end * scale
        else:
            start, end = y + start * height, y + end * height
        if end <= start:
            raise ValueError('Expected a descending vertical gradient.')
        result = Image.new('RGBA', image.size)
        draw = ImageDraw.Draw(result)
        for row in range(extent):
            fraction = min(stops[-1][0], max(stops[0][0], (row - start) / (end - start)))
            for (left, top), (right, bottom) in zip(stops, stops[1:]):
                if left <= fraction <= right:
                    weight = (fraction - left) / (right - left)
                    color = tuple(round(a + (b - a) * weight) for a, b in zip(top, bottom))
                    draw.line((0, row, extent - 1, row), fill=(*color, 255))
                    break
        return result

    def paint(item):
        layer = Image.new('RGBA', image.size)
        kind = item.tag.rsplit('}', 1)[-1]
        if kind in ('title', 'desc', 'defs'):
            return layer
        attributes = item.attrib
        if kind == 'g':
            for child in item:
                layer.alpha_composite(paint(child))
        elif kind == 'rect':
            if attributes['fill'] != 'url(#tile)':
                raise ValueError('Unsupported background fill.')
            x, y, width, height, radius = [
                round(float(attributes[key]) * scale)
                for key in ('x', 'y', 'width', 'height', 'rx')]
            mask = Image.new('L', image.size)
            ImageDraw.Draw(mask).rounded_rectangle(
                (x, y, x + width - 1, y + height - 1), radius, fill=255)
            gradient = gradient_fill(attributes['fill'], (x, y, width, height))
            layer.paste(gradient, (0, 0), mask)
            if 'stroke' in attributes:
                # SVG strokes straddle the shape's edge. Pillow draws inward,
                # so expand the outline bounds by half its width.
                border = round(float(attributes['stroke-width']) * scale)
                half = border / 2
                ImageDraw.Draw(layer).rounded_rectangle(
                    (x - half, y - half, x + width - 1 + half, y + height - 1 + half),
                    radius + half, outline=attributes['stroke'], width=border)
        elif kind in ('polyline', 'line'):
            if kind == 'polyline':
                points = [tuple(float(v) * scale for v in point.split(','))
                          for point in attributes['points'].split()]
            else:
                points = [(float(attributes[f'x{i}']) * scale,
                           float(attributes[f'y{i}']) * scale) for i in (1, 2)]
            width = round(float(attributes['stroke-width']) * scale)
            color = attributes['stroke']
            gradient = gradient_fill(color, (0, 0, extent, extent)) if color.startswith('url(') else None
            if gradient is not None:
                color = '#FFFFFF'
            draw = ImageDraw.Draw(layer)
            draw.line(points, fill=color, width=width, joint='curve')
            for x, y in points:
                radius = width / 2
                draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)
            if gradient is not None:
                gradient.putalpha(layer.getchannel('A'))
                layer = gradient
        else:
            raise ValueError(f'Unsupported SVG primitive: {kind}')
        if 'filter' in attributes:
            reference = attributes['filter']
            if not reference.startswith('url(#') or not reference.endswith(')'):
                raise ValueError('Unsupported SVG filter reference.')
            definition = filters[reference[5:-1]]
            if len(definition) != 1 or definition[0].tag != f'{{{namespace["s"]}}}feDropShadow':
                raise ValueError('Expected one drop shadow per filter.')
            effect = definition[0].attrib
            dx, dy = [round(float(effect[key]) * scale) for key in ('dx', 'dy')]
            opacity = float(effect['flood-opacity'])
            if not 0 <= opacity <= 1:
                raise ValueError('Invalid shadow opacity.')
            alpha = Image.new('L', layer.size)
            alpha.paste(layer.getchannel('A'), (dx, dy))
            alpha = alpha.filter(ImageFilter.GaussianBlur(float(effect['stdDeviation']) * scale))
            alpha = alpha.point(lambda value: round(value * opacity))
            shadow = Image.new('RGBA', layer.size, ImageColor.getrgb(effect['flood-color']))
            shadow.putalpha(alpha)
            shadow.alpha_composite(layer)
            return shadow
        return layer

    for item in source:
        image.alpha_composite(paint(item))
    return image.resize((1024, 1024), Image.Resampling.LANCZOS)


def outputs():
    image = render()
    result = {}
    targets = {ROOT / 'branding/ashapp.png': 1024,
               ROOT / 'flutter/assets/branding/app_icon.png': 128}
    mac = ROOT / 'flutter/macos/Runner/Assets.xcassets/AppIcon.appiconset'
    targets.update({mac / f'app_icon_{size}.png': size for size in SIZES})
    for target, size in targets.items():
        content = io.BytesIO()
        image.resize((size, size), Image.Resampling.LANCZOS).save(content, format='PNG')
        result[target] = content.getvalue()
    content = io.BytesIO()
    image.save(content, format='ICO', sizes=[(size, size) for size in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
    result[ROOT / 'flutter/windows/runner/resources/app_icon.ico'] = content.getvalue()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify generated assets without writing.')
    args = parser.parse_args()
    for target, content in outputs().items():
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                raise SystemExit(f'Icon needs regeneration: {target.relative_to(ROOT)}')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    print('Ashapp icon assets match the SVG.' if args.check else 'Generated Ashapp icon assets.')


if __name__ == '__main__':
    main()
