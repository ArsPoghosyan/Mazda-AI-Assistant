# Google sign-in artwork

`google-g.png` is Google's unmodified standard gradient G icon, used with the
visible "Sign in with Google" label inside one responsive full-width HTML button.
The icon uses object-contain to preserve its original 200 by 204 aspect ratio.

- Source: https://developers.google.com/static/identity/images/g-logo.png
- SHA-256: `d1ce9c2af0b10a7333abc99bc706f9a6a199e5b65bf3e3009624f076b8638e6a`
- Reviewed: 2026-10-23
- Use: Google sign-in only, under the HTML/custom-button option documented at
  https://developers.google.com/identity/branding-guidelines

The authored HTML button uses Google's documented dark theme colors, the font
fallback from its official HTML configurator, fixed logo proportions and visible
action text. It adds no Google SDK, tracking script or remote font request.

Google provides this icon for this sign-in use. Preserve the
artwork, proportions and attribution. The Google marks/artwork are not licensed
under this repository's MIT license; no endorsement or unrestricted reuse is
claimed. No Google font or third-party runtime script is included by this asset.

## askm6 tab icon

`frontend/public/favicon.svg` is an original geometric `a6` monogram under the
repository's MIT license. It uses the site's teal (`#6ba99f`) and navy (`#0f172a`),
with vector paths for consistent rendering without fonts or external requests.
The SVG is served from `/favicon.svg` on the landing and policy pages.
