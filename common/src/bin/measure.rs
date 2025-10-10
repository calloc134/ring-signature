use anyhow::{anyhow, Result};
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION, generate_keypair, ring::ring_sign, rsa::PublicKey,
};
use plotters::prelude::*;
use rand::thread_rng;
use std::env;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

struct Config {
    min_size: usize,
    max_size: usize,
    step: usize,
    iters: usize,
    rsa_bits: usize,
    csv_path: String,
    png_path: String,
    message: String,
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    fn get<T: std::str::FromStr>(args: &[String], key: &str, default: T) -> T {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == key {
                if let Some(v) = it.next() {
                    if let Ok(p) = v.parse::<T>() {
                        return p;
                    }
                }
            }
        }
        default
    }
    fn get_s(args: &[String], key: &str, default: &str) -> String {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == key {
                if let Some(v) = it.next() {
                    return v.to_string();
                }
            }
        }
        default.to_string()
    }
    Config {
        min_size: get(&args, "--min", 2usize),
        max_size: get(&args, "--max", 64usize),
        step: get(&args, "--step", 2usize),
        iters: get(&args, "--iters", 10usize),
        rsa_bits: get(&args, "--rsa-bits", 2048usize),
        csv_path: get_s(&args, "--csv", "ring_sign_times.csv"),
        png_path: get_s(&args, "--png", "ring_sign_time.png"),
        message: get_s(&args, "--msg", "Benchmark: Ring signature"),
    }
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / n;
    (mean, var.sqrt())
}

fn draw_plot(
    data_avg: &[(usize, f64)],
    iters: usize,
    rsa_bits: usize,
    png_path: &str,
) -> Result<()> {
    let root = BitMapBackend::new(png_path, (960, 640)).into_drawing_area();
    root.fill(&WHITE)?;

    let x_min = data_avg.first().map(|(x, _)| *x as i32).unwrap_or(0);
    let x_max = data_avg
        .last()
        .map(|(x, _)| *x as i32)
        .unwrap_or(1)
        .max(x_min + 1);
    let y_max = data_avg
        .iter()
        .map(|(_, y)| *y)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let y_max = (y_max * 1.10).ceil();

    let mut chart = ChartBuilder::on(&root)
        .caption(
            format!(
                "Ring signing time vs ring size (RSA {}-bit, iters {})",
                rsa_bits, iters
            ),
            ("sans-serif", 28).into_font(),
        )
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(x_min..x_max, 0f64..y_max)?;

    chart
        .configure_mesh()
        .x_desc("Ring size (number of public keys)")
        .y_desc("Mean signing time (ms)")
        .x_labels(10)
        .y_labels(10)
        .light_line_style(&WHITE.mix(0.3))
        .draw()?;

    // 折れ線
    chart
        .draw_series(LineSeries::new(
            data_avg.iter().map(|(x, y)| (*x as i32, *y)),
            &RED,
        ))?
        .label("mean")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], &RED));

    // 各点をプロット
    chart.draw_series(
        data_avg
            .iter()
            .map(|(x, y)| Circle::new((*x as i32, *y), 3, RED.filled())),
    )?;

    chart
        .configure_series_labels()
        .border_style(&BLACK)
        .background_style(&WHITE.mix(0.8))
        .draw()?;

    // 出力を確定（エラーを検出可能に）
    root.present()?; // Plottersの推奨に従い明示的にpresentを呼ぶ
    Ok(())
}

fn main() -> Result<()> {
    // ロガーは未初期化のまま（logマクロはno-op）。計測に余計なオーバーヘッドを入れないため。

    let cfg = parse_args();
    if cfg.min_size < 2 || cfg.min_size > cfg.max_size {
        return Err(anyhow!(
            "Invalid range: --min must be >= 2 and <= --max (got min={}, max={})",
            cfg.min_size,
            cfg.max_size
        ));
    }
    if cfg.step == 0 {
        return Err(anyhow!("--step must be >= 1"));
    }

    println!(
        "Generating {} RSA keypairs ({}-bit)...",
        cfg.max_size, cfg.rsa_bits
    );
    let mut rng = thread_rng();
    let mut ring_keypairs = Vec::with_capacity(cfg.max_size);
    for _ in 0..cfg.max_size {
        ring_keypairs.push(generate_keypair(cfg.rsa_bits, &mut rng)?);
    }
    println!("Key generation done.");

    // CSVヘッダ
    let mut csv = File::create(&cfg.csv_path)?;
    writeln!(csv, "ring_size,iter,elapsed_ms")?;

    let message = cfg.message.as_bytes();
    let mut data_avg: Vec<(usize, f64)> = Vec::new();

    let mut size = cfg.min_size;
    while size <= cfg.max_size {
        // リング（公開鍵）を先頭から size 件利用。署名者は index 0。
        let ring_pubs: Vec<PublicKey> = ring_keypairs
            .iter()
            .take(size)
            .map(|kp| kp.public.clone())
            .collect();
        let signer_index = 0usize;

        // 共通ドメイン b を計算
        let b = ring_pubs
            .iter()
            .map(|pk| pk.n.bits() as usize)
            .max()
            .unwrap()
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // ウォームアップ（計測に含めない）
        let _ = ring_sign(
            &ring_pubs,
            signer_index,
            &ring_keypairs[signer_index].secret,
            message,
            b,
        )?;

        // 計測 iters 回
        let mut times_ms: Vec<f64> = Vec::with_capacity(cfg.iters);
        for it in 0..cfg.iters {
            let t0 = Instant::now();
            let _sig = ring_sign(
                &ring_pubs,
                signer_index,
                &ring_keypairs[signer_index].secret,
                message,
                b,
            )?;
            let dt_ms = t0.elapsed().as_secs_f64() * 1000.0;
            times_ms.push(dt_ms);
            writeln!(csv, "{},{},{}", size, it, dt_ms)?;
        }

        let (mean_ms, std_ms) = mean_std(&times_ms);
        println!(
            "ring_size = {:>3}: mean = {:>8.3} ms, std = {:>8.3} ms (iters = {})",
            size, mean_ms, std_ms, cfg.iters
        );
        data_avg.push((size, mean_ms));

        // 次のサイズへ
        size = size.saturating_add(cfg.step);
    }

    // グラフ出力
    draw_plot(&data_avg, cfg.iters, cfg.rsa_bits, &cfg.png_path)?;
    println!("CSV -> {}", cfg.csv_path);
    println!("PNG -> {}", cfg.png_path);
    println!("Done.");
    Ok(())
}
