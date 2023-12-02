package peoplefinder.DELETE.api.users.__id

default allowed = false

default visible = false

default enabled = false

allowed {
	props = input.user.properties
	props.department == "Operations"
	props.title == "IT Manager"
}

visible {
	props = input.user.properties
	props.department == "Operations"
}

enabled {
	allowed
}
