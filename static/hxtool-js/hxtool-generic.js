function hxtool_ajax_post_request(endpoint, mydata, successCallback, contentType=false) {
	$.ajax
	({
		type: "POST",
		url: endpoint,
		dataType: 'json',
		contentType: contentType,
		processData: false,
		data: mydata,
		success: successCallback,
		error: hxtoolActionFail
	})
}

function hxtool_ajax_get_request(endpoint, myargs, successCallback) {
	$.ajax
	({
		url: endpoint,
		dataType: 'json',
		contentType: 'application/json',
		data: myargs,
		success: successCallback,
		error: hxtoolActionFail
	})
}

function hxtoolActionFail(xhr,status,error) {
	$("#hxtoolMessageBody").html(JSON.stringify(xhr['responseText']));
	$("#hxtoolMessage").show();
}


function getHistoricDate(days) {
	var historicDate = new Date();
	historicDate.setDate(historicDate.getDate() - days);
	return(historicDate.toISOString().substr(0, 10))
}

function updateChartJS(name, url) {
	var jsonData = $.ajax({
		url: url,
		dataType: 'json',
	}).done(function (myChartData) {
		name.data = myChartData;
		name.options.animation.duration = 0;
		name.update();
	});
}

var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = window.location.search.substring(1),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : decodeURIComponent(sParameterName[1]);
        }
    }
};

function hxtoolGenerateNestedTable(myData) {
	var r = "<table class='hxtool_table_host_alert hxtool_table'>";
	r += "<tbody>";
	$.each( myData, function( index, value ) {
		r += "<tr>";
		r += "<td class='hxtool_host_info_cell'>" + index + "</td>";
		r += "<td>";
		if (isObject(value)) {
			r += hxtoolGenerateNestedTable(value);
		}
		else {
			r += value;
		}
		r += "</td>";
		r += "</tr>";
	});
	r += "</tbody>";
	r += "</table>";
	return(r);
}

function hxtoolGenerateNestedObjectView(myData) {
	var r = "";
	console.log(myData);
	$.each( myData, function( index, value ) {
		r += "<div>";
		r += index + ": ";
		if (isObject(value)) {
			hxtoolGenerateNestedObjectView(value);
		}
		else {
			r += value;
		}
		r += "</div>";
	});
}

function isObject(obj) {
	return obj === Object(obj);
}
