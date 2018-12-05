function hxtool_ajax_post_request(endpoint, mydata, successCallback) {
	$.ajax
	({
		type: "POST",
		url: endpoint,
		dataType: 'json',
		contentType: false,
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

