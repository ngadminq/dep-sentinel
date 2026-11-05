const es = require('event-stream');

process.stdin.pipe(es.split()).pipe(es.mapSync(line => line.toUpperCase() + '\n')).pipe(process.stdout);
