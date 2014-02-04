try {
    module.exports = require('./build/default/wfutil.node');
} catch(e) {
    module.exports = require('./build/Release/wfutil.node');
}