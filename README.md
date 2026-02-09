# Personal Website with Blog

This site is built with [11ty (Eleventy)](https://www.11ty.io/) - a simple static site generator.

## Quick Start

### Development Server
```bash
# From /home/henry/clawd/
npm run dev
```
This starts a dev server at http://localhost:8080 with hot reload.

### Build for Production
```bash
# From /home/henry/clawd/
npm run build
```
Output goes to `personal-site/_site/`

### Serve Built Site
```bash
cd personal-site/_site && python3 -m http.server 8000
```
Access at http://192.168.0.100:8000 (local network)

## Adding Blog Posts

1. Create a new Markdown file in `personal-site/blog/`
2. Add front matter at the top:
```yaml
---
title: Your Post Title
date: 2025-02-08
tags: blog
excerpt: Short description for the blog listing
---
```

3. Write your content in Markdown below the front matter
4. Build and serve: `npm run build`

## File Structure

```
personal-site/
├── _includes/
│   ├── layout.njk     # Main layout template
│   └── post.njk       # Individual blog post template
├── _site/             # Built output (don't edit)
├── blog/
│   ├── automation.md  # Example blog post
│   └── welcome.md     # Example blog post
├── blog.njk           # Blog listing page
└── index.njk          # Home page
```

## Markdown in Posts

You can use standard Markdown:
- **Bold** and *italic*
- [Links](https://example.com)
- `inline code`
- ```code blocks```
- Headings (##, ###)
- Lists

## Styling

All CSS is inline in the layout template. To customize the look, edit `_includes/layout.njk`.
