const _ = require('lodash');

function summarize(rows) {
  const valid = rows.filter(r => _.get(r, 'meta.valid', false));
  return _.map(_.groupBy(valid, 'region'), (items, region) => ({
    region, total: _.sumBy(items, 'amount'), top: _.pick(_.maxBy(items, 'amount'), ['id', 'amount']),
  }));
}

module.exports = { summarize };
