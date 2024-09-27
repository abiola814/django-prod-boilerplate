TRANSACTION_STATUS_CHOICES = (
    ("success", "Success"),
    ("pending", "Pending"),
    ("failed", "Failed"),
)

DAY_OF_THE_WEEK_CHOICES = (
    ("0", "Sunday"),
    ("1", "Monday"),
    ("2", "Tuesday"),
    ("3", "Wednesday"),
    ("4", "Thursday"),
    ("5", "Friday"),
    ("6", "Saturday"),
)

APPROVE_OR_DECLINE_CHOICES = (
    ("approved", "Approve"),
    ("declined", "Decline"),
    ("pending", "Pending"),
)

ACCOUNT_TIER_CHOICES = (("tier1", "Tier 1"), ("tier2", "Tier 2"), ("tier3", "Tier 3"))

TRANSFER_TYPE_CHOICES = (("samebank", "Same Bank"), ("otherbank", "Other Bank"))

BENEFICIARY_TYPE_CHOICES = (
    ("samebank", "Same Bank"),
    ("otherbank", "Other Bank"),
    ("airtime", "Airtime"),
    ("data", "Data"),
    ("electricity", "Electricity"),
    ("payattitude", "Payattitude"),
    ("cable", "Cable"),
    ("betting", "Betting"),
)

GENDER_TYPE_CHOICES = (("male", "Male"), ("female", "Female"))

RELATIONSHIP_STATUS_CHOICES = (
    ("-", "---"),
    ("brother", "Brother"),
    ("sister", "Sister"),
    ("son", "Son"),
    ("daughter", "Daughter"),
    ("spouse", "Spouse"),
    ("mother", "Mother"),
    ("father", "Father"),
)

TRANSACTION_PIN_SET_ACTION_CHOICES = (("new", "New"), ("change", "Change"))

INVESTMENT_DURATION_CHOICES = (
    (90, "90 Days"),
    (180, "180 Days"),
    (270, "270 Days"),
    (365, "365 Days"),
)

INVESTMENT_STATUS_CHOICES = (
    ("running", "Running"),
    ("matured", "Matured"),
    ("paid", "Paid"),
    ("reinvested", "Re-Invested"),
)

AIRTIME_DATA_CHOICES = (("airtime", "Airtime"), ("data", "Data"))

BILL_PAYMENT_VALIDATION_CHOICES = (
    ("cable", "CableTV"),
    ("meter", "Meter No."),
    ("betting", "Betting"),
)

LOAN_TYPE_CHOICES = (("sme", "SME"), ("rent", "Rent"), ("salary", "Salary Advance"))

INVESTMENT_HISTORY_CHOICES = (("funded", "Funded"), ("withdrawal", "Withdrawal"))

INVESTMENT_WITHDRAWAL_CHOICES = (("part", "Partial Amount"), ("full", "Full Amount"))

INVESTMENT_TYPE = (
    ("premium", "Premium"),
    ("basic", "Basic"),
    ("exclusive", "Exclusive"),
    ("essential", "Essential"),
    ("elite", "Elite"),
    ("prestige", "Prestige"),
    ("advance", "Advance"),
)
