"use strict";

ckan.module('user-edit-form-sso', function($, _) {
    return {

        allow_checkbox: $("#user_custom_profile_data"),
        user_details: $("#field-username, #field-fullname, #field-email"),
        user_password: $("#field-password, #field-password-confirm"),

        initialize: function() {
            $.proxyAll(this, /_on/);
            if (this.options.name_id !== 'None') {
                var config_user_change = this.options.config_user_change.toLowerCase() === 'true';
                var user_allow_update = this.options.user_allow_update.toLowerCase() === 'true';
                this.user_password.attr("readonly", true);
                if (!config_user_change || (config_user_change && !user_allow_update)) {
                    this.user_details.attr("readonly", true);
                }
                this.allow_checkbox.on('click', this._onCheckboxClick);
            }
        },

        _onCheckboxClick: function(event) {
            if (this.allow_checkbox.prop('checked')) {
                this.user_details.attr("readonly", false);
                this.allow_checkbox.val("True");
            } else {
                this.user_details.attr("readonly", true);
                this.allow_checkbox.val("False");
            }
        }
    }
});
