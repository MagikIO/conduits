/* eslint-disable n/no-unpublished-require */
const tseslint = require('typescript-eslint');
const { LintGolem } = require('@magik_io/lint_golem');

module.exports = tseslint.config(
  ...new LintGolem({ rootDir: __dirname }).config
)
