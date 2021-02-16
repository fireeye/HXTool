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

	$("#hxtool_topnavSearch").click(function(e) {
		myWidth = $("#hxtool_topnavSearch").closest("div").width();

		if ($("#hxtool_topnavSearch").data("clicked") == false) {
			$("#hxtool_topnavSearch").closest("div").animate({
				width: myWidth + 235
			}, 200, function() {
				$("#hxtool_topnav_left_container-search").show();
				$("#hxtool_topnavSearch").data("clicked", true);
				$("#hxtool_global_search").focus();
			});
		}
		else {
			$("#hxtool_topnav_left_container-search").hide();
			$("#hxtool_topnavSearch").closest("div").animate({
				width: myWidth - 235
			}, 200, function() {
				$("#hxtool_topnavSearch").data("clicked", false);
			});
		}
		e.stopPropagation();
	});

	$("#hxtool_global_search").keypress(function (e) {
		var key = e.which;
		if(key == 13) {
			location.href = "/hostsearch?q=" + $("#hxtool_global_search").val();
		}
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
		$(this).closest("div").parent().find("button").html($(this).find(".fe-dropdown__item-link-text").html() + "<i class='fe-icon--right fas fa-chevron-up'></i>");
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

	/* Detects when OS scaling is active and resizes HXTool to avoid it, doesn't work in FF */
	if (window.devicePixelRatio !== 1 && screen.width <= 1920) {
		console.log("HXTool: OS Scaling active. Enforcing HXTool scaling");
	    let scaleValue = (1/window.devicePixelRatio);
	    $(document.body).css('zoom',scaleValue);
	    var myNewHeight = (window.innerHeight * window.devicePixelRatio);
	    $(".hxtool5_container").css('min-height',myNewHeight);
	    $(".hxtool5_container").css('max-height',myNewHeight);
	    $(".hxtool5_container").css('height',myNewHeight);
		$(".hxtool5_content").css('min-height',myNewHeight - 60);
	    $(".hxtool5_content").css('max-height',myNewHeight - 60);
	    $(".hxtool5_content").css('height',myNewHeight - 60);
	    $(".panelAlertsClass").css('height',myNewHeight - 290);
	    $(".panelContentClass").css('height',myNewHeight - 290);
	    $(".panelAcqClass").css('height',myNewHeight - 290);
	    $(".hxtool_panel_stackinganalyze").css('min-height',myNewHeight - 190);
	    $(".hxtool_panel_scriptbuilder").css('height',myNewHeight - 120);
	    $(".hxtool_scriptbuilder_scriptarea").css('height',myNewHeight - 450);
	}

}