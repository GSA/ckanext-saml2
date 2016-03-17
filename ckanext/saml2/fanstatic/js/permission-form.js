ckan.module('permission-form', function($, _) {
  "use strict";
  return {
    initialize: function() {
      $.proxyAll(this, /_on/);

      this.client = ckan.sandbox().client;
      this.permboxes = $("input[name=perm]", this.el);
      this.username = $('#username', this.el);
      this.username.on('change', this._onChangeUser);
    },

    _onChangeUser: function(e){
      var self = this;
      this.cleanPerms()

      this.client.call(
        'POST',
        'access_permission_show',
        {id: e.target.value},
        function(data){
          if(data.result)
            self.permboxes.map(function(i, elem){
              var perms = data.result.permissions;
              if(~perms.indexOf(elem.id.slice('perm_'.length)))
                elem.checked = true;
            });
        });
    },

    cleanPerms: function(){
      this.permboxes.removeAttr('checked');
    }
  }
})
