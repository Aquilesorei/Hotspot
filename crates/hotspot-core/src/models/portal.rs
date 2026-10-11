use serde::{Deserialize, Serialize};

use crate::constants::{PORTAL_DEFAULT_COUNTRY_CODE, PORTAL_DEFAULT_DURATIONS_MIN};
use crate::error::{HotspotError as E, Result};

/// Fixed when the profile is created: a password network can't turn into a portal, or back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    #[default]
    Standard,
    /// Open Wi-Fi; devices get internet after entering a coupon on the captive portal.
    Portal,
}

/// How a coupon's duration is spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeMode {
    /// Runs from activation, even while the device is away.
    #[default]
    Real,
    /// Only counts while the device is connected.
    Connected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalSettings {
    /// Preselected in the form's country list.
    #[serde(default = "default_country_code")]
    pub country_code: String,
    /// Durations offered when creating coupons, in minutes.
    #[serde(default = "default_durations")]
    pub durations_min: Vec<u64>,
    /// Defaults for new coupon batches.
    #[serde(default)]
    pub time_mode: TimeMode,
    #[serde(default = "default_devices")]
    pub devices_per_coupon: u32,
}

impl Default for PortalSettings {
    fn default() -> Self {
        Self {
            country_code: default_country_code(),
            durations_min: default_durations(),
            time_mode: TimeMode::default(),
            devices_per_coupon: default_devices(),
        }
    }
}

fn default_country_code() -> String {
    PORTAL_DEFAULT_COUNTRY_CODE.into()
}

fn default_durations() -> Vec<u64> {
    PORTAL_DEFAULT_DURATIONS_MIN.to_vec()
}

fn default_devices() -> u32 {
    1
}

/// `+` then 1 to 4 digits, no leading zero: `+91`, `+1`, `+1268`.
pub fn validate_country_code(code: &str) -> Result<()> {
    let digits = code.strip_prefix('+').unwrap_or("");
    let valid = (1..=4).contains(&digits.len()) && !digits.starts_with('0') && digits.bytes().all(|b| b.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(E::invalid_profile(format!("country code {code:?}: expected + and 1 to 4 digits")))
    }
}

/// ITU calling codes, sorted by country name.
pub const COUNTRY_CODES: &[(&str, &str)] = &[
    ("Afghanistan", "+93"), ("Albania", "+355"), ("Algeria", "+213"), ("Andorra", "+376"), ("Angola", "+244"),
    ("Argentina", "+54"), ("Armenia", "+374"), ("Australia", "+61"), ("Austria", "+43"), ("Azerbaijan", "+994"),
    ("Bahrain", "+973"), ("Bangladesh", "+880"), ("Belarus", "+375"), ("Belgium", "+32"), ("Benin", "+229"),
    ("Bhutan", "+975"), ("Bolivia", "+591"), ("Bosnia and Herzegovina", "+387"), ("Botswana", "+267"), ("Brazil", "+55"),
    ("Brunei", "+673"), ("Bulgaria", "+359"), ("Burkina Faso", "+226"), ("Burundi", "+257"), ("Cambodia", "+855"),
    ("Cameroon", "+237"), ("Canada", "+1"), ("Cape Verde", "+238"), ("Central African Republic", "+236"), ("Chad", "+235"),
    ("Chile", "+56"), ("China", "+86"), ("Colombia", "+57"), ("Comoros", "+269"), ("Congo", "+242"),
    ("Congo (DRC)", "+243"), ("Costa Rica", "+506"), ("Côte d'Ivoire", "+225"), ("Croatia", "+385"), ("Cuba", "+53"),
    ("Cyprus", "+357"), ("Czechia", "+420"), ("Denmark", "+45"), ("Djibouti", "+253"), ("Dominican Republic", "+1"),
    ("Ecuador", "+593"), ("Egypt", "+20"), ("El Salvador", "+503"), ("Equatorial Guinea", "+240"), ("Eritrea", "+291"),
    ("Estonia", "+372"), ("Eswatini", "+268"), ("Ethiopia", "+251"), ("Fiji", "+679"), ("Finland", "+358"),
    ("France", "+33"), ("Gabon", "+241"), ("Gambia", "+220"), ("Georgia", "+995"), ("Germany", "+49"),
    ("Ghana", "+233"), ("Greece", "+30"), ("Guatemala", "+502"), ("Guinea", "+224"), ("Guinea-Bissau", "+245"),
    ("Haiti", "+509"), ("Honduras", "+504"), ("Hong Kong", "+852"), ("Hungary", "+36"), ("Iceland", "+354"),
    ("India", "+91"), ("Indonesia", "+62"), ("Iran", "+98"), ("Iraq", "+964"), ("Ireland", "+353"),
    ("Israel", "+972"), ("Italy", "+39"), ("Jamaica", "+1"), ("Japan", "+81"), ("Jordan", "+962"),
    ("Kazakhstan", "+7"), ("Kenya", "+254"), ("Kuwait", "+965"), ("Kyrgyzstan", "+996"), ("Laos", "+856"),
    ("Latvia", "+371"), ("Lebanon", "+961"), ("Lesotho", "+266"), ("Liberia", "+231"), ("Libya", "+218"),
    ("Liechtenstein", "+423"), ("Lithuania", "+370"), ("Luxembourg", "+352"), ("Macau", "+853"), ("Madagascar", "+261"),
    ("Malawi", "+265"), ("Malaysia", "+60"), ("Maldives", "+960"), ("Mali", "+223"), ("Malta", "+356"),
    ("Mauritania", "+222"), ("Mauritius", "+230"), ("Mexico", "+52"), ("Moldova", "+373"), ("Monaco", "+377"),
    ("Mongolia", "+976"), ("Montenegro", "+382"), ("Morocco", "+212"), ("Mozambique", "+258"), ("Myanmar", "+95"),
    ("Namibia", "+264"), ("Nepal", "+977"), ("Netherlands", "+31"), ("New Zealand", "+64"), ("Nicaragua", "+505"),
    ("Niger", "+227"), ("Nigeria", "+234"), ("North Korea", "+850"), ("North Macedonia", "+389"), ("Norway", "+47"),
    ("Oman", "+968"), ("Pakistan", "+92"), ("Palestine", "+970"), ("Panama", "+507"), ("Papua New Guinea", "+675"),
    ("Paraguay", "+595"), ("Peru", "+51"), ("Philippines", "+63"), ("Poland", "+48"), ("Portugal", "+351"),
    ("Qatar", "+974"), ("Romania", "+40"), ("Russia", "+7"), ("Rwanda", "+250"), ("Saudi Arabia", "+966"),
    ("Senegal", "+221"), ("Serbia", "+381"), ("Seychelles", "+248"), ("Sierra Leone", "+232"), ("Singapore", "+65"),
    ("Slovakia", "+421"), ("Slovenia", "+386"), ("Somalia", "+252"), ("South Africa", "+27"), ("South Korea", "+82"),
    ("South Sudan", "+211"), ("Spain", "+34"), ("Sri Lanka", "+94"), ("Sudan", "+249"), ("Suriname", "+597"),
    ("Sweden", "+46"), ("Switzerland", "+41"), ("Syria", "+963"), ("Taiwan", "+886"), ("Tajikistan", "+992"),
    ("Tanzania", "+255"), ("Thailand", "+66"), ("Togo", "+228"), ("Trinidad and Tobago", "+1"), ("Tunisia", "+216"),
    ("Turkey", "+90"), ("Turkmenistan", "+993"), ("Uganda", "+256"), ("Ukraine", "+380"), ("United Arab Emirates", "+971"),
    ("United Kingdom", "+44"), ("United States", "+1"), ("Uruguay", "+598"), ("Uzbekistan", "+998"), ("Venezuela", "+58"),
    ("Vietnam", "+84"), ("Yemen", "+967"), ("Zambia", "+260"), ("Zimbabwe", "+263"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes() {
        for ok in ["+91", "+1", "+1268"] {
            assert!(validate_country_code(ok).is_ok(), "{ok}");
        }
        for bad in ["91", "+", "+091", "+12345", "+9a", ""] {
            assert!(validate_country_code(bad).is_err(), "{bad}");
        }
    }
}
