(function ( $ ) {
  $.fn.progress = function() {
    var percent = this.data("percent");
    this.html("<div class='hxtool_progress' style='width: 0;'>"+percent+"%</div>");
    this.find("div").animate({ width: percent+"%" });
  };
}( jQuery ));
