module.exports = function(eleventyConfig) {
  // Copy static files to output
  eleventyConfig.addPassthroughCopy("personal-site/css");
  eleventyConfig.addPassthroughCopy("personal-site/images");

  // Date formatting filter
  eleventyConfig.addFilter("dateDisplay", (date) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  });

  return {
    dir: {
      input: "personal-site",
      output: "personal-site/_site"
    }
  };
};
