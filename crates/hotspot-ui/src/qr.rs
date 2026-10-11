use qrcode::{Color, QrCode};
use slint::{Image, Rgba8Pixel, SharedPixelBuffer};

const QUIET_ZONE: usize = 4;
const TARGET_PX: usize = 200;

/// Standard Wi-Fi join payload understood by phone cameras. Hidden networks need `H:true`
/// or phones keep scanning for a broadcast that never comes.
pub fn wifi_payload(ssid: &str, password: &str, hidden: bool) -> String {
    let escape = |s: &str| {
        s.chars().fold(String::new(), |mut out, c| {
            if "\\;,:\"".contains(c) {
                out.push('\\');
            }
            out.push(c);
            out
        })
    };
    let hidden = if hidden { "H:true;" } else { "" };
    format!("WIFI:T:WPA;S:{};P:{};{hidden};", escape(ssid), escape(password))
}

/// Black on white with a quiet zone, scaled by a whole number so modules stay sharp.
pub fn render(payload: &str) -> Option<Image> {
    let code = QrCode::new(payload).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let modules = width + 2 * QUIET_ZONE;
    let scale = (TARGET_PX / modules).max(1);
    let size = modules * scale;

    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(size as u32, size as u32);
    let pixels = buffer.make_mut_slice();
    for y in 0..size {
        for x in 0..size {
            let (mx, my) = (x / scale, y / scale);
            let inside = (QUIET_ZONE..QUIET_ZONE + width).contains(&mx) && (QUIET_ZONE..QUIET_ZONE + width).contains(&my);
            let dark = inside && colors[(my - QUIET_ZONE) * width + (mx - QUIET_ZONE)] == Color::Dark;
            let v = if dark { 0 } else { 255 };
            pixels[y * size + x] = Rgba8Pixel { r: v, g: v, b: v, a: 255 };
        }
    }
    Some(Image::from_rgba8(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_escapes_special_characters() {
        assert_eq!(wifi_payload("TestHS", "motdepasse123", false), "WIFI:T:WPA;S:TestHS;P:motdepasse123;;");
        assert_eq!(wifi_payload("TestHS", "motdepasse123", true), "WIFI:T:WPA;S:TestHS;P:motdepasse123;H:true;;");
        assert_eq!(wifi_payload(r#"a;b,c:d"e\f"#, "p;w", false), r#"WIFI:T:WPA;S:a\;b\,c\:d\"e\\f;P:p\;w;;"#);
    }
}
