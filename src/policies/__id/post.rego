package peoplefinder.POST.api.users.__id

default allowed = false

default visible = true

default enabled = false

allowed {
	props = input.user.properties
	props.department == "Operations"
}

enabled {
	allowed
}
