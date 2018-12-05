function hxtoolAddInput(title, name, id, placeholder, hint) {

	html = '<div class="hxtool_panel_wrapper">';
		html += '<label for="" class="fe-input-label caption">' + title + '</label>';
		html += '<input type="text" id="' + id + '" name="' + name + '" value="" class="fe-input" placeholder="' + placeholder + '" />';
		html += '<span class="fe-input-hint-text">' + hint + '</span>';
	html += '</div>';

	return(html);
}