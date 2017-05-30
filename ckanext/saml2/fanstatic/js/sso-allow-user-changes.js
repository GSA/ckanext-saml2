"use strict";

ckan.module('sso-user-allow', function($, _) {
    return {

        allow_checkbox: $("input[name=user_custom_profile_data]"),
        checked_checkbox: null,

        initialize: function() {
            $.proxyAll(this, /_on/);
            this.allow_checkbox.on('click', this._onCheckboxClick);
        },

        _onCheckboxClick: function(event) {
            this.checked_checkbox = this.allow_checkbox.prop('checked');
            if (this.checked_checkbox) {
                $("input[name=name]").attr("readonly", false);
                $("input[name=fullname]").attr("readonly", false);
                $("input[name=email]").attr("readonly", false);
            } else {
                $("input[name=name]").attr("readonly", true);
                $("input[name=fullname]").attr("readonly", true);
                $("input[name=email]").attr("readonly", true);
            }
        }
    }
});
