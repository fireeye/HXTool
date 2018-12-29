function hxtoolAddInput(title, name, id, placeholder, hint) {

	html = '<div class="hxtool_panel_wrapper">';
		html += '<label for="" class="fe-input-label caption">' + title + '</label>';
		html += '<input type="text" id="' + id + '" name="' + name + '" value="" class="fe-input" placeholder="' + placeholder + '" />';
		html += '<span class="fe-input-hint-text">' + hint + '</span>';
	html += '</div>';

	return(html);
}


function generateDropDown(elementValue, elementId, elementDefault, entries=[{}], elementAdditionalClass, elementLabel) {
	var r = "";

	// Header
	r += "<div class='fe-dropdown";
	if (elementAdditionalClass != false) { r += " " + elementAdditionalClass; }
	r += "'>";
		r += '<button type="button" id="' + elementId + '" data-id="' + elementDefault + '" class="fe-btn fe-btn--sm fe-btn--hxtool-main"> ' + elementValue + ' <i class="fe-icon--right fal fa-chevron-up"></i></button>';
		r += '<div class="fe-dropdown__list-container">';
			r += '<ul class="fe-dropdown__list fe-list">';

				//List
				$.each( entries, function( dkey, dvalue ) {
					r += '<li class="fe-dropdown__item">';
						r += '<a class="fe-dropdown__item-link">';
							r += '<span class="fe-dropdown__item-link-left-section">';
								r += '<i style="margin-top: 2px;" class="fas ' + dvalue['elementIcon'] + ' fa-lg"></i>';
							r += '</span>';
							r += '<span class="fe-dropdown__item-link-text" data-id="' + dvalue['elementId'] + '">' + dvalue['elementText'] + '</span>';
						r += '</a>';
					r += "</li>";
				});

			//Footer
			r += "</ul>";
		r += "</div>";
	r += "</div>";

	// Label
	if (elementLabel != false) {
		r += "<br><span class='fe-input-hint-text'>" + elementLabel + "</span><br>";
	}

	r += "<br>";

	return(r);
}


/*

	<div class='fe-dropdown{% if elementAdditionalClass != "" %} {{elementAdditionalClass}}{% endif %}'>
		<button type="button" id="{{elementId}}" data-id="{{elementDefault}}" class="fe-btn fe-btn--sm fe-btn--hxtool-main"> {{elementValue}} <i class="fe-icon--right fal fa-chevron-up"></i></button>
		<div class="fe-dropdown__list-container">
			<ul class="fe-dropdown__list fe-list">

				<li class="fe-dropdown__item">
					<a class="fe-dropdown__item-link">
						<span class="fe-dropdown__item-link-left-section">
							<i style='margin-top: 2px;' class="fas {{elementIcon}} fa-lg"></i>
						</span>
						<span class="fe-dropdown__item-link-text" data-id="{{elementId}}">{{elementText}}</span>
					</a>
				</li>			

			</ul>
		</div>
	</div>
	<br>
	<span class="fe-input-hint-text">{{elementLabel}}</span><br>
*/