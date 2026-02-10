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

1. Create a new Markdown file in `personal-site/content/blog/`
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

## Deployment to Surge.sh

```bash
# From /home/henry/clawd/
npm run build
cd personal-site/_site
surge --domain henrybergstrom.surge.sh
```

## File Structure

```
personal-site/
├── _config/
│   └── filters.js     # Custom Nunjucks filters
├── _data/
│   ├── eleventyDataSchema.js
│   └── metadata.js     # Site metadata
├── _includes/
│   ├── css/            # CSS files
│   ├── layouts/        # Page layout templates
│   │   ├── base.njk   # Base layout
│   │   ├── home.njk   # Home page
│   │   └── post.njk   # Blog post layout
│   └── postslist.njk   # Blog posts list component
├── _site/              # Built output (don't edit)
├── content/
│   ├── blog/           # Blog posts
│   │   ├── automation.md
│   │   ├── welcome.md
│   │   └── web-security-for-juniors.md
│   ├── blog.njk        # Blog listing page
│   └── index.njk       # Home page
├── public/             # Static assets
└── .eleventy.js        # Eleventy configuration
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
