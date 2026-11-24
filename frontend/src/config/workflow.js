// Allowed status changes. This mirrors backend/app/models/enums.py so the UI
// only offers valid buttons; the backend still enforces the same rules.

export const ALERT_TRANSITIONS = {
  new: ['investigating', 'resolved', 'false_positive'],
  investigating: ['resolved', 'false_positive', 'new'],
  resolved: ['closed', 'investigating'],
  false_positive: ['closed', 'investigating'],
  closed: ['investigating'],
}

export const INCIDENT_TRANSITIONS = {
  new: ['investigating', 'false_positive'],
  investigating: ['contained', 'resolved', 'false_positive'],
  contained: ['resolved', 'investigating'],
  resolved: ['closed', 'investigating'],
  false_positive: ['closed', 'investigating'],
  closed: ['investigating'],
}

export const NEEDS_RESOLUTION = ['resolved', 'false_positive', 'closed']
