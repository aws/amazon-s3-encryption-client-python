/**
 * Semantic Release configuration for Amazon S3 Encryption Client for Python.
 *
 * Determines the next version from conventional commits, updates pyproject.toml,
 * generates release notes, and creates a GitHub release.
 */
module.exports = {
  branches: ["main"],
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { type: "feat", release: "minor" },
          { type: "fix", release: "patch" },
          { type: "perf", release: "patch" },
          { type: "revert", release: "patch" },
          { breaking: true, release: "major" },
        ],
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits",
        presetConfig: {
          types: [
            { type: "feat", section: "Features" },
            { type: "fix", section: "Bug Fixes" },
            { type: "perf", section: "Performance" },
            { type: "revert", section: "Reverts" },
            { type: "docs", section: "Documentation", hidden: false },
            { type: "chore", section: "Maintenance", hidden: false },
            { type: "refactor", section: "Refactoring", hidden: false },
            { type: "test", section: "Tests", hidden: true },
            { type: "ci", section: "CI", hidden: true },
          ],
        },
      },
    ],
    [
      "@semantic-release/exec",
      {
        prepareCmd:
          'sed -i "s/^version = .*/version = \\"${nextRelease.version}\\"/" pyproject.toml',
      },
    ],
    [
      "@semantic-release/changelog",
      {
        changelogFile: "CHANGELOG.md",
      },
    ],
    [
      "@semantic-release/git",
      {
        assets: ["pyproject.toml", "CHANGELOG.md"],
        message:
          "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
      },
    ],
    [
      "@semantic-release/github",
      {
        draftRelease: true,
      },
    ],
  ],
};
