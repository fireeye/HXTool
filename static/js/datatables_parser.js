function datatables_parseHostlink(data) {
	myArr = data.split("___");
	data = '<a class="hostLink" href="/hosts?host=' + encodeURIComponent(myArr[1]) + '">' + myArr[0] + '</a>';
	return(data);
}

function datatables_parsePlatform(data) {
	if (data == "win") {
		data = '<i class="fab fa-windows fa-2x fa-fw" style="margin-right: 2px; color: rgb(73, 110, 150);" aria-hidden="true"></i>';
	}
	else if (data == "osx") {
		data = '<i class="fab fa-apple fa-2x fa-fw" style="margin-right: 2px; color: rgb(127, 127, 127);" aria-hidden="true"></i>';
	}
	else if (data == "linux") {
		data = '<i class="fab fa-linux fa-2x fa-fw" style="margin-right: 2px; color: rgb(42, 53, 58);" aria-hidden="true"></i>';
	}
	else {
		data = "N/A"
	}
	return(data);	
}

function datatables_parseAcquisitionType(data) {
	if (data == "triage") {
		data = "<i class='fas fa-medkit fa-lg fa-fw' style='margin-right: 2px; color: green;' aria-hidden='true'></i><b>Triage</b>";
	}
	else if (data == "live") {
		data = "<i class='fas fa-database fa-lg fa-fw' style='margin-right: 2px; color: #0f468e;' aria-hidden='true'></i><b>Acquisition</b>";
	}
	else if (data == "file") {
		data = "<i class='fas fa-file fa-lg fa-fw' style='margin-right: 2px; color: #840f8e;' aria-hidden='true'></i><b>File</b>";
	}
	else {
		data = data;
	}
	return(data);
}

function datatables_parseAcquisitionState(data) {
	if (data == "QUEUED") {
		data = "<i class='fas fa-clock fa-lg fa-fw' style='margin-right: 2px; color: #840f8e;' aria-hidden='true'></i><b>Queued</b>";
	}
	else if (data == "RUNNING") {
		data = "<i class='fas fa-hdd fa-lg fa-fw' style='margin-right: 2px; color: #d1cd17;' aria-hidden='true'></i><b>Running</b>";
	}
	else if (data == "COMPLETE") {
		data = "<i class='fas fa-check-square fa-lg fa-fw' style='margin-right: 2px; color: green;' aria-hidden='true'></i><b>Complete</b>";
	}
	else {
		data = data;
	}
	return(data);	
}

function datatables_parseContainmentState(data) {
	if (data == "normal") {
		data = "<i class='fas fa-lock-open fa-lg fa-fw' style='margin-right: 2px; color: green;' aria-hidden='true'></i><b>Normal</b>";
	}
	else if (data == "containing") {
		data = "<i class='fas fa-unlock fa-lg fa-fw' style='margin-right: 2px; color: #cc9216;' aria-hidden='true'></i><b>Containing</b>";
	}
	else if (data == "uncontain") {
		data = "<i class='fas fa-unlock fa-lg fa-fw' style='margin-right: 2px; color: #cc9216;' aria-hidden='true'></i><b>Uncontain</b>";
	}
	else if (data == "uncontaining") {
		data = "<i class='fas fa-unlock fa-lg fa-fw' style='margin-right: 2px; color: #cc9216;' aria-hidden='true'></i><b>Uncontaining</b>";
	}
	else if (data == "contain") {
		data = "<i class='fas fa-unlock fa-lg fa-fw' style='margin-right: 2px; color: #cc9216;' aria-hidden='true'></i><b>Contain</b>";
	}
	else if (data == "contained") {
		data = "<i class='fas fa-lock fa-lg fa-fw' style='margin-right: 2px; color: #d11717;' aria-hidden='true'></i><b>Contained</b>";
	}
	else {
		data = data;
	}
	return(data);

}