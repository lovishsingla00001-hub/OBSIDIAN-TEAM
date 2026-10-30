/**
 * @fileoverview Main Rules Index for SiteCheck.
 * Aggregates all security rule suites across headers, tls, exposure, and html.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 */

const headerRules = require('./headers');
const tlsRules = require('./tls');
const exposureRules = require('./exposure');
const htmlRules = require('./html');

/** @type {import('../core/types').Rule[]} */
const allRules = [
  ...headerRules,
  ...tlsRules,
  ...exposureRules,
  ...htmlRules,
];

module.exports = allRules;
module.exports.allRules = allRules;
module.exports.headerRules = headerRules;
module.exports.tlsRules = tlsRules;
module.exports.exposureRules = exposureRules;
module.exports.htmlRules = htmlRules;
