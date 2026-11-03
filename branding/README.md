# Ashapp identity

The selected identity is **Carbon**: a raised warm off-white A followed by small warm-gray lowercase `sh` on a rounded charcoal tile, spelling **Ash**. A thin outline keeps the tile visible on dark backgrounds. `ashapp.svg` is the editable source. All lettering uses geometric strokes, no external image or font. The source and generated assets use the repository's MIT license.

The owner finalized Carbon by selecting the retained candidate again after a five-round comparison, then requested a warmer palette. The final artwork preserves the selected shape, bevels, depth and shadows while using warm charcoal and off-white colors. Draft alternatives remain outside the public repository.

The [logo-generator skill](https://github.com/op7418/logo-generator-skill) informed the targeted refinement of the established A + sh direction: one focal point, generous negative space, restrained color and readable desktop sizes. This is editable vector artwork; the skill's optional Gemini presentation-image service is not needed to regenerate the application assets.

Two restrained shadows give the tile and lettering a little depth. They are defined as SVG drop-shadow filters and rendered locally from the same parameters; transparent padding is preserved in the PNG and ICO exports.

The A itself has visible relief: a shaded side offset down and right, a beveled rim and a lighter front face. Each surface uses its own SVG gradient, so the depth remains editable vector artwork and appears in every generated icon size.

The repository README references the shared PNG so GitHub displays the same mark as the application. Keep the SVG and PNG in the public source tree with the application icons.

The mark is shared by the application toolbar, Windows executable, taskbar, shortcuts, Windows Setup/uninstall and the macOS application icon. macOS builds its application `.icns` from the Xcode AppIcon image set; the system PKG file and macOS Installer keep their standard system appearance.

Version v0.0.6 introduces this identity. Native release packages use the checked-in icons; confirm the uploaded assets before treating a source change as a published installer.

To regenerate assets after editing the SVG, from the repository root:

```sh
python -m pip install -r tool/icon-requirements.txt
python tool/generate_app_icons.py
python tool/generate_app_icons.py --check
```

The development-only renderer supports the simple SVG primitives used by this logo. Extend it deliberately if the source gains new shapes. PNG assets include all seven macOS sizes (16–1024), a 128-pixel Flutter image and a 1024-pixel preview. The Windows ICO includes 16, 20, 24, 32, 40, 48, 64, 128 and 256-pixel frames. Generation is local; release builds use the checked-in images and do not need Pillow.
