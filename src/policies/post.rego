package peoplefinder.POST.api.users

default allowed = false

default visible = false

default enabled = false

allowed {
	props = input.user.properties
	props.department == "Operations"
	props.title == "IT Manager"
}

visible {
	allowed
}

enabled {
	allowed
}
