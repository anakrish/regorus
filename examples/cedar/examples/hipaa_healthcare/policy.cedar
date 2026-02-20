// HIPAA-inspired healthcare data access.
//
// Doctors in the "oncology" department may view patient records,
// but only during approved hours and from a trusted device.
// Nurses may view records too, but never if the patient has
// restricted access ("VIP" flag).

permit(
  principal in Role::"doctors",
  action == Action::"viewRecord",
  resource == PatientRecord::"chart-42"
)
when {
  principal.department == "oncology" &&
  context.hour >= 8 &&
  context.hour <= 18 &&
  context.device_trusted == true
};

permit(
  principal in Role::"nurses",
  action == Action::"viewRecord",
  resource == PatientRecord::"chart-42"
)
when {
  resource.vip == false &&
  context.hour >= 6 &&
  context.hour <= 20
};

// Night-time access is always denied for non-emergency.
forbid(
  principal,
  action == Action::"viewRecord",
  resource == PatientRecord::"chart-42"
)
when {
  context.emergency == false &&
  (context.hour < 6 || context.hour > 22)
};
