from calculator import add_numbers, average_numbers, label_status


def startup_check() -> dict[str, object]:
    sample_total = add_numbers(8, 3)
    return {
        "status": "ok",
        "sample_total": sample_total,
        "sample_average": average_numbers([10, 20, 30]),
        "label": label_status(12),
    }


if __name__ == "__main__":
    summary = startup_check()
    print(
        "startup-check:"
        f" status={summary['status']}"
        f" sample_total={summary['sample_total']}"
        f" sample_average={summary['sample_average']}"
        f" label={summary['label']}"
    )
