(function ( $ ) {
  $.fn.progress = function() {
    var percent = this.data("percent");
    this.css("width", percent+"%");
	this.html("<div class='htBarContent'>"+percent+"%</div>");
  };
}( jQuery ));
