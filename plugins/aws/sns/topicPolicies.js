var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Policies',
    category: 'SNS',
    description: 'Ensures SNS topics do not allow global send or subscribe.',
    more_info: 'SNS policies should not be configured to allow any AWS user to subscribe or send messages. This could result in data leakage or financial DDoS.',
    recommended_action: 'Adjust the topic policy to only allow authorized AWS users in known accounts to subscribe.',
    link: 'http://docs.aws.amazon.com/sns/latest/dg/AccessPolicyLanguage.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.sns, function(region, rcb){
            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SNS topics: ' + helpers.addError(listTopics), region);
                return rcb();
            }

            if (!listTopics.data.length) {
                helpers.addResult(results, 0, 'No SNS topics found', region);
                return rcb();
            }

            async.each(listTopics.data, function(topic, cb){
                if (!topic.TopicArn) return cb();

                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, topic.TopicArn]);

                if (!getTopicAttributes ||
                    (!getTopicAttributes.err && !getTopicAttributes.data)) return cb();

                if (getTopicAttributes.err || !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic for policy: ' + helpers.addError(getTopicAttributes),
                        region, topic.TopicArn);

                    return cb();
                }

                if (!getTopicAttributes.data.Attributes ||
                    !getTopicAttributes.data.Attributes.Policy) {
                    helpers.addResult(results, 3,
                        'The SNS topic does not have a policy attached.',
                        region, topic.TopicArn);

                    return cb();
                }

                try {
                    var policy = JSON.parse(getTopicAttributes.data.Attributes.Policy);
                } catch (e) {
                    helpers.addResult(results, 3,
                        'The SNS topic policy is not valid JSON.',
                        region, topic.TopicArn);

                    return cb();
                }

                var actions = [];

                if (policy.Statement && policy.Statement.length) {
                    for (var s in policy.Statement) {
                        var statement = policy.Statement[s];

                        // Evaluates whether the effect of the statement is to "allow" access to the SNS
                        var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);

                        // Evaluates whether the principal is open to everyone/anonymous
                        var principalEval = (statement.Principal && statement.Principal.AWS &&
                                            (statement.Principal.AWS === '*' || statement.Principal.AWS === 'arn:aws:iam::*') ? true : false);

                        // Evaluate the condition:
                        // Does the condition exist?
                        var conditionExists = (statement.Condition ? true : false);
                        // Is it a string condition (StringEquals)? Is the SourceOwner open to everyone?
                        var conditionString = ((statement.Condition && statement.Condition.StringEquals &&
                            (statement.Condition.StringEquals['aws:SourceOwner'] || !statement.Condition.StringEquals['aws:SourceOwner'] == '*')) ? true : false);
                        // Is it an arn condition (ArnEquals)? Is the SourceArn open to all arns?
                        var conditionArn = false;
                        if (statement.Condition && statement.Condition.ArnEquals &&
                            statement.Condition.ArnEquals['aws:SourceArn'] &&
                            statement.Condition.ArnEquals['aws:SourceArn'] == '*') {
                            conditionArn = true;
                        }
                        // Summarize the condition results
                        var statementEval = ((conditionExists && (conditionString || conditionArn)) ? false : true);

                        if (effectEval && principalEval && statementEval) {
                            if (statement.Action && typeof statement.Action === 'string') {
                                if (actions.indexOf(statement.Action) === -1) {
                                    actions.push(statement.Action);
                                }
                            } else if (statement.Action && statement.Action.length) {
                                for (var a in statement.Action) {
                                    if (actions.indexOf(statement.Action[a]) === -1) {
                                        actions.push(statement.Action[a]);
                                    }
                                }
                            }
                        }
                    }
                }

                if (actions.length) {
                    helpers.addResult(results, 2,
                        'The SNS topic policy allows global access to the action(s): ' + actions,
                        region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0,
                        'The SNS topic policy does not allow global access.',
                        region, topic.TopicArn);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
