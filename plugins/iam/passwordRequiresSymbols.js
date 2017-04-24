var helpers = require('../../helpers');

module.exports = {
	title: 'Password Requires Symbols',
	category: 'IAM',
	description: 'Ensures password policy requires the use of symbols',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Update the password policy to require the use of symbols',
	apis: ['IAM:getAccountPasswordPolicy'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var getAccountPasswordPolicy = helpers.addSource(cache, source,
				['iam', 'getAccountPasswordPolicy', region]);

		if (!getAccountPasswordPolicy) return callback(null, results, source);

		if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
			helpers.addResult(results, 3, 'Unable to query for password policy status');
			return callback(null, results, source);
		}

		var passwordPolicy = getAccountPasswordPolicy.data;

		if (!passwordPolicy.RequireSymbols) {
			helpers.addResult(results, 1, 'Password policy does not require symbols');
		} else {
			helpers.addResult(results, 0, 'Password policy requires symbols');
		}

		callback(null, results, source);
	}
};