function collapse_all_dropdowns() {
	$(".fe-dropdown__list-container").each(function() {
		$(this).css("opacity", 0);
		$(this).hide();
	});
}

function hxtool_doc_ready() { 

	/* Global stuff */

	// Set the background to proper gradient size depending on browser width
	// var myGradient = "radial-gradient(" + Math.round($( window ).width() * 0.52) + "px at 50% 0%, #355881 0%, #222 100%)";
	// $("body").css({ "background": myGradient });


	$(document).click(function(e) {
		// Collapse all top navbar dropdowns
		$(".hxtool_topnav_dropdown").hide(100);

		// Collapse all drop-down menus
		collapse_all_dropdowns();
	
		e.stopPropagation();
	});

	$("#hxtoolMessageCancel").click(function(e) {
		$("#hxtoolMessage").hide();
		e.stopPropagation();
	});

	/* TOP NAV BAR */
	$(".hxtool_topnav_mainbutton").click(function(e) {
		if($(this).attr("data-link") !== undefined) {
			window.location.href = $(this).attr('data-link');
		}
		else {
			$(".hxtool_topnav_dropdown").hide(100);
			$(this).next("div").show(100);
		}
		e.stopPropagation();
	});

	$(".hxtool_topnav_dropdown_child").click(function(e) {
		window.location.href = $(this).attr('data-link');
		e.stopPropagation();
	});

	$("#hxtoolLogout").click(function(e) {
		window.location.href = "/logout"
		e.stopPropagation();
	});

	/* Panel */

	// show/hide panel
	$(".hxtool-panel-toggle").click(function(e) {
		if ($(this).closest("div").next("div").css("display") == "none") {
			$(this).closest("div").next("div").show(200);
		}
		else {
			$(this).closest("div").next("div").hide(200);
		}
	});

	/* DROP DOWN MENUS */
	$(document).on("click", ".fe-dropdown", function(e) {
		collapse_all_dropdowns();
		$(this).find("div").show();
		$(this).find("div").fadeTo( "fast" , 1);
		e.stopPropagation();
	});

	$(document).on("click", ".fe-dropdown__item-link", function(e) {
		$(this).closest("div").parent().find("button").html($(this).find(".fe-dropdown__item-link-text").html() + "<i class='fe-icon--right fal fa-chevron-up'></i>");
		$(this).closest("div").parent().find("button").data("id", $(this).find(".fe-dropdown__item-link-text").data("id") );
		$(this).closest("div").fadeTo( "fast", 0, function() {
			$(".fe-dropdown__list-container").hide();
		});

		e.stopPropagation();
	});

	/* MODAL */
	$(".fe-modal-close").click(function(){
		$(this).closest("div").parent().parent().parent().parent().hide();
	});


	/////// LEGACY REMOVE

	$('[id^=navbutton]').click(function() {
		url = this.id.split("_");
		window.location.replace("/" + url[1]);
	});

	$('#ht_info').click(function(e) {
		$('#ht_info_content').show(150);
		e.stopPropagation();
	});
	
	$(document).click(function() {
		$("#dropdown-content-indicators").hide();
		$("#dropdown-content-admin").hide();
		$("#dropdown-content-acquisition").hide();
		$("#dropdown-content-es").hide();
		$('#ht_info_content').hide();
		$("#dropdown-content-dashboard").hide();
		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});
	});
	
	$('[id^=dropdown-content]').click(function(e) {
		 e.stopPropagation();
	});

	$("#navcategory_acquisition").click(function(e) {

		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});

		$("#dropdown-content-admin").hide();
		$("#dropdown-content-indicators").hide();
		$("#dropdown-content-es").hide();
		$("#dropdown-content-dashboard").hide();
		$('#ht_info_content').hide();

		$(this).css({"border-top": "1px solid #151515"});
		$(this).css({"border-left": "1px solid #151515"});
		$(this).css({"border-right": "1px solid #151515"});
		$(this).css({"border-bottom": "1px solid #eee"});

		$("#dropdown-content-acquisition").show(0);

		e.stopPropagation();
	});
	
	$("#navcategory_indicator").click(function(e) {

		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});

		$("#dropdown-content-admin").hide();
		$("#dropdown-content-acquisition").hide();
		$("#dropdown-content-es").hide();
		$("#dropdown-content-dashboard").hide();
		$('#ht_info_content').hide();

		$(this).css({"border-top": "1px solid #151515"});
		$(this).css({"border-left": "1px solid #151515"});
		$(this).css({"border-right": "1px solid #151515"});
		$(this).css({"border-bottom": "1px solid #eee"});

		$("#dropdown-content-indicators").show(0);
		e.stopPropagation();
	});

	$("#navcategory_admin").click(function(e) {

		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});

		$("#dropdown-content-indicators").hide();
		$("#dropdown-content-acquisition").hide();
		$("#dropdown-content-es").hide();
		$("#dropdown-content-dashboard").hide();
		$('#ht_info_content').hide();

		$(this).css({"border-top": "1px solid #151515"});
		$(this).css({"border-left": "1px solid #151515"});
		$(this).css({"border-right": "1px solid #151515"});
		$(this).css({"border-bottom": "1px solid #eee"});

		$("#dropdown-content-admin").show(0);
		e.stopPropagation();
	});

	$("#navcategory_es").click(function(e) {

		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});

		$("#dropdown-content-admin").hide();
		$("#dropdown-content-indicators").hide();
		$("#dropdown-content-acquisition").hide();
		$("#dropdown-content-dashboard").hide();
		$('#ht_info_content').hide();

		$(this).css({"border-top": "1px solid #151515"});
		$(this).css({"border-left": "1px solid #151515"});
		$(this).css({"border-right": "1px solid #151515"});
		$(this).css({"border-bottom": "1px solid #eee"});

		$("#dropdown-content-es").show(0);
		e.stopPropagation();
	});

	$("#navcategory_dashboard").click(function(e) {

		$('#htLayoutTopBarMenuContainer').children('div').each(function () {
			$(this).css({"border": "1px solid transparent"});
		});

		$("#dropdown-content-admin").hide();
		$("#dropdown-content-indicators").hide();
		$("#dropdown-content-acquisition").hide();
		$("#dropdown-content-es").hide();
		$('#ht_info_content').hide();

		$(this).css({"border-top": "1px solid #151515"});
		$(this).css({"border-left": "1px solid #151515"});
		$(this).css({"border-right": "1px solid #151515"});
		$(this).css({"border-bottom": "1px solid #eee"});

		$("#dropdown-content-dashboard").show(0);
		e.stopPropagation();
	});


}