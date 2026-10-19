#!/usr/bin/env python3
"""CTF image header repair; Python standard library only."""

import argparse
import json
from pathlib import Path
import struct
import sys
import zlib

VERSION = "1.0.0"
LIMIT = 256 * 1024 * 1024
PNG = b"\x89PNG\r\n\x1a\n"
SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
       0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


class ImageError(ValueError):
    """Unsupported, inconsistent or truncated image."""


def require(condition, message):
    if not condition:
        raise ImageError(message)


def read_image(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Файл превышает --max-mib.")
    return data


def parse_png(data):
    chunks = []
    pos = 8
    bad = []
    while pos < len(data):
        require(pos + 12 <= len(data), "Обрезанный заголовок PNG chunk.")
        size, kind = struct.unpack_from(">I4s", data, pos)
        end = pos + 12 + size
        require(end <= len(data), "Обрезанный PNG chunk.")
        payload = data[pos + 8:end - 4]
        crc = struct.unpack_from(">I", data, end - 4)[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != crc:
            bad.append({"type": kind.decode("ascii", "replace"), "offset": pos})
        chunks.append((kind, pos, size))
        pos = end
        if kind == b"IEND":
            require(size == 0, "Некорректный IEND.")
            break
    require(chunks and chunks[0][:3:2] == (b"IHDR", 13), "Нет корректного первого IHDR.")
    require(chunks[-1][0] == b"IEND", "Нет IEND.")
    require(sum(k == b"IHDR" for k, _, _ in chunks) == 1, "Несколько IHDR.")
    require(any(k == b"IDAT" for k, _, _ in chunks), "Нет IDAT.")
    width, height, depth, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", data, 16)
    valid = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8},
             4: {8, 16}, 6: {8, 16}}
    require(color in valid and depth in valid[color], "Неверные color type / bit depth PNG.")
    require(compression == filtering == 0 and interlace in (0, 1), "Неподдерживаемый метод PNG.")
    require(0 < width <= 0x7FFFFFFF and 0 < height <= 0x7FFFFFFF, "Неверные размеры PNG.")
    return {"format": "PNG", "width": width, "height": height,
            "bit_depth": depth, "color_type": color, "interlace": interlace,
            "bad_crc": bad, "trailing_bytes": len(data) - pos,
            "animated": any(k == b"acTL" for k, _, _ in chunks), "_chunks": chunks}


def parse_bmp(data):
    require(len(data) >= 26, "Обрезанный BMP.")
    file_size, offset, dib = (struct.unpack_from("<I", data, p)[0] for p in (2, 10, 14))
    require(dib in (12, 40, 52, 56, 108, 124), "Неподдерживаемый DIB-заголовок BMP.")
    require(14 + dib <= len(data), "Обрезанный DIB-заголовок.")
    if dib == 12:
        width, height, planes, bpp = struct.unpack_from("<HHHH", data, 18)
        compression, size_image = 0, None
    else:
        width, height, planes, bpp, compression, size_image = struct.unpack_from("<iiHHII", data, 18)
    require(width > 0 and height != 0 and planes == 1, "Неверная геометрия BMP.")
    require(bpp in (1, 4, 8, 16, 24, 32), "Неподдерживаемая глубина BMP.")
    require(14 + dib <= offset <= len(data), "Некорректный pixel offset BMP.")
    palette_entries = (1 << bpp) if bpp <= 8 else 0
    if dib != 12:
        used = struct.unpack_from("<I", data, 46)[0]
        palette_entries = used or palette_entries
    mask_bytes = (12 if compression == 3 else 16 if compression == 6 else 0) if dib == 40 else 0
    require(14 + dib + mask_bytes + palette_entries * (3 if dib == 12 else 4) <= offset,
            "BMP pixel offset пересекает палитру или маски.")
    end = len(data)
    profile = False
    if dib == 124:
        profile_offset, profile_size = struct.unpack_from("<II", data, 126)
        if profile_size:
            start = 14 + profile_offset
            require(start >= 14 + dib and start + profile_size <= len(data), "Обрезанный BMP color profile.")
            if start >= offset:
                end = start
                profile = True
            else:
                require(start + profile_size <= offset, "BMP color profile пересекает пиксели.")
    stride = ((width * bpp + 31) // 32) * 4
    return {"format": "BMP", "width": width, "height": abs(height),
            "top_down": height < 0, "bits_per_pixel": bpp, "compression": compression,
            "stride": stride, "pixel_bytes_available": end - offset,
            "declared_file_size": file_size, "declared_pixel_bytes": size_image,
            "color_profile_after_pixels": profile, "_dib": dib, "_offset": offset}


def parse_jpeg(data):
    pos = 2
    frame = None
    while pos < len(data):
        require(data[pos] == 0xFF, "Неверный JPEG marker.")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        require(pos < len(data), "Обрезанный JPEG marker.")
        marker = data[pos]
        pos += 1
        if marker in (0xDA, 0xD9):
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        require(marker not in (0, 0xD8), "Неверный JPEG marker до SOS.")
        require(pos + 2 <= len(data), "Обрезанная длина JPEG segment.")
        size = struct.unpack_from(">H", data, pos)[0]
        require(size >= 2 and pos + size <= len(data), "Обрезанный JPEG segment.")
        if marker in SOF:
            require(frame is None, "Несколько JPEG frames не поддерживаются.")
            require(size >= 8, "Обрезанный JPEG SOF.")
            depth, height, width, components = struct.unpack_from(">BHHB", data, pos + 2)
            require(size == 8 + 3 * components and components > 0, "Неверный JPEG SOF.")
            require(width > 0 and height > 0, "JPEG с DNL/нулевыми размерами не поддерживается.")
            frame = {"format": "JPEG", "width": width, "height": height,
                     "precision": depth, "components": components,
                     "sof_marker": f"FF{marker:02X}", "_height_offset": pos + 3,
                     "_width_offset": pos + 5}
        pos += size
    require(frame is not None, "JPEG SOF не найден.")
    return frame


def parse(data):
    if data.startswith(PNG):
        return parse_png(data)
    if data.startswith(b"BM"):
        return parse_bmp(data)
    if data.startswith(b"\xff\xd8"):
        return parse_jpeg(data)
    raise ImageError("Неизвестная сигнатура. Поддерживаются PNG, BMP, JPEG; расширение не учитывается.")


def inflate_png(data, info, limit):
    """Bound decompressed bytes, including on hostile highly compressible inputs."""
    stream = zlib.decompressobj()
    output = bytearray()
    extra = 0
    try:
        for kind, pos, size in info["_chunks"]:
            if kind != b"IDAT":
                continue
            payload = data[pos + 8:pos + 8 + size]
            if stream.eof:
                extra += len(payload)
                continue
            output.extend(stream.decompress(payload, limit + 1 - len(output)))
            require(len(output) <= limit and not stream.unconsumed_tail,
                    "Распакованный IDAT превышает --max-mib.")
            extra += len(stream.unused_data)
        require(stream.eof, "Обрезанный zlib-поток IDAT.")
    except zlib.error as exc:
        raise ImageError(f"Ошибка zlib IDAT: {exc}") from exc
    return output, extra


def infer(data, info, width=None, limit=LIMIT):
    width = info["width"] if width is None else width
    require(0 < width <= 0x7FFFFFFF, "Ширина должна быть в диапазоне 1..2147483647.")
    fmt = info["format"]
    if fmt == "PNG":
        require(not info["animated"], "Автовосстановление APNG не поддерживается.")
        require(info["interlace"] == 0, "Для Adam7 задайте размеры вручную через set.")
        raw, extra = inflate_png(data, info, limit)
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[info["color_type"]]
        stride = 1 + (width * channels * info["bit_depth"] + 7) // 8
        height, remainder = divmod(len(raw), stride)
        require(height > 0 and remainder == 0,
                f"IDAT не делится на полные строки ширины {width}: остаток {remainder} байт.")
        require(all(raw[pos] <= 4 for pos in range(0, len(raw), stride)),
                "Неверные filter bytes: ширина не соответствует строкам PNG.")
        require(height <= 0x7FFFFFFF, "Вычисленная высота слишком велика.")
        return {"width": width, "height": height, "row_bytes_with_filter": stride,
                "inflated_bytes": len(raw), "extra_compressed_bytes": extra,
                "basis": "IDAT row length and filter bytes"}
    if fmt == "BMP":
        require(info["compression"] in (0, 3, 6), "Автовосстановление сжатых BMP не поддерживается.")
        stride = ((width * info["bits_per_pixel"] + 31) // 32) * 4
        height, remainder = divmod(info["pixel_bytes_available"], stride)
        require(height > 0 and remainder == 0,
                f"Область BMP не делится на строки ширины {width}: остаток {remainder} байт.")
        require(height <= (65535 if info["_dib"] == 12 else 0x7FFFFFFF), "Высота BMP вне диапазона.")
        return {"width": width, "height": height, "stride": stride,
                "basis": "available pixel bytes; arbitrary trailing data may look like rows"}
    raise ImageError("JPEG: автоматический вывод высоты не поддерживается. Используйте set или sweep.")


def patch(data, info, width=None, height=None):
    width = info["width"] if width is None else width
    height = info["height"] if height is None else height
    fmt = info["format"]
    maximum = 65535 if fmt == "JPEG" or (fmt == "BMP" and info["_dib"] == 12) else 0x7FFFFFFF
    require(0 < width <= maximum and 0 < height <= maximum, f"Размеры должны быть в диапазоне 1..{maximum}.")
    out = bytearray(data)
    if fmt == "PNG":
        require(not info["animated"], "Изменение APNG не поддерживается.")
        struct.pack_into(">II", out, 16, width, height)
        struct.pack_into(">I", out, 29, zlib.crc32(out[12:29]) & 0xFFFFFFFF)
    elif fmt == "BMP":
        require(info["compression"] in (0, 3, 6), "Изменение сжатых BMP не поддерживается.")
        stride = ((width * info["bits_per_pixel"] + 31) // 32) * 4
        pixel_size = stride * height
        require(pixel_size <= info["pixel_bytes_available"], "В BMP недостаточно байтов для этих размеров.")
        require(len(data) <= 0xFFFFFFFF and pixel_size <= 0xFFFFFFFF, "BMP превышает 32-битные размеры.")
        if info["_dib"] == 12:
            struct.pack_into("<HH", out, 18, width, height)
        else:
            struct.pack_into("<ii", out, 18, width, -height if info["top_down"] else height)
            struct.pack_into("<I", out, 34, pixel_size)
        struct.pack_into("<I", out, 2, len(data))
    else:
        struct.pack_into(">H", out, info["_width_offset"], width)
        struct.pack_into(">H", out, info["_height_offset"], height)
    return bytes(out)


def write_output(path, data, source, force=False):
    path = Path(path)
    source = Path(source)
    require(path.resolve() != source.resolve(), "Выходной путь совпадает с исходником.")
    if path.exists():
        require(not path.samefile(source), "Выходной файл является ссылкой на исходник.")
    # Exclusive creation by default; never silently overwrite a previous result.
    with path.open("wb" if force else "xb") as stream:
        stream.write(data)


def positive(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Ожидается целое число.") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("Ожидается положительное число.")
    return number


def height_range(value):
    try:
        start, stop, step = map(int, value.split(":"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Формат: START:STOP:STEP, STOP включительно.") from exc
    if start <= 0 or stop < start or step <= 0:
        raise argparse.ArgumentTypeError("Нужны 0 < START <= STOP, STEP > 0.")
    if (stop - start) // step + 1 > 256:
        raise argparse.ArgumentTypeError("Не более 256 вариантов за один запуск.")
    return range(start, stop + 1, step)


def extension(info):
    return {"PNG": ".png", "BMP": ".bmp", "JPEG": ".jpg"}[info["format"]]


def warnings(info):
    result = []
    if info["format"] == "PNG":
        if info["bad_crc"]:
            result.append("Есть несовпадения CRC; set/recover пересчитывает только IHDR.")
        if info["trailing_bytes"]:
            result.append("После IEND есть данные; это отдельная область, не дополнительные строки IDAT.")
        if info["animated"]:
            result.append("APNG: доступна только диагностика.")
    elif info["format"] == "BMP":
        result.append("Автовысота BMP — кандидат: произвольный хвост может быть принят за пиксели.")
    else:
        result.append("JPEG: изменение SOF не создаёт пиксели; слишком большой размер может дать ошибки декодера.")
    return result


def build_parser():
    parser = argparse.ArgumentParser(description="CTF: восстановление размеров PNG/BMP/JPEG без hex-редактора.")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("inspect", "Формат, размеры и кандидат на полную высоту"),
        ("recover", "Автоматически восстановить высоту PNG/BMP"),
        ("set", "Записать размеры в заголовок; PNG IHDR CRC пересчитывается"),
        ("sweep", "Создать серию файлов с разной высотой"),
    ):
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("input", type=Path)
        sub.add_argument("--max-mib", type=positive, default=256, help="Лимит чтения и распаковки в MiB (256)")
        sub.add_argument("--width", type=positive, help="Новая/предполагаемая ширина")
        if command == "inspect":
            sub.add_argument("--json", action="store_true", help="Машиночитаемый отчёт")
        else:
            sub.add_argument("--force", action="store_true", help="Перезаписать существующий результат")
        if command in ("set", "recover"):
            sub.add_argument("-o", "--output", type=Path)
        if command == "set":
            sub.add_argument("--height", type=positive, help="Новая высота; без размеров исправляется IHDR CRC PNG")
        if command == "sweep":
            sub.add_argument("--heights", type=height_range, required=True, metavar="START:STOP:STEP")
            sub.add_argument("-d", "--output-dir", type=Path, required=True)
    return parser


def run(args):
    data = read_image(args.input, args.max_mib * 1024 * 1024)
    info = parse(data)
    notes = warnings(info)
    if args.command == "inspect":
        report = {k: v for k, v in info.items() if not k.startswith("_")}
        report["warnings"] = notes
        try:
            report["candidate"] = infer(data, info, args.width, args.max_mib * 1024 * 1024)
        except ImageError as exc:
            report["auto_error"] = str(exc)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(f"{info['format']}: {info['width']} x {info['height']}")
            for key, value in report.items():
                if key not in ("format", "width", "height", "warnings"):
                    print(f"{key}: {value}")
            for note in notes:
                print(f"Примечание: {note}")
        return
    for note in notes:
        print(f"Примечание: {note}", file=sys.stderr)
    if args.command == "sweep":
        # Validate every candidate and collision before creating the first file.
        outputs = []
        for height in args.heights:
            path = args.output_dir / f"{args.input.stem}_{args.width or info['width']}x{height}{extension(info)}"
            patch(data, info, args.width, height)
            require(path.resolve() != args.input.resolve(), "Вариант совпадает с исходником.")
            if path.exists():
                require(not path.samefile(args.input), "Вариант является ссылкой на исходник.")
                require(args.force and path.is_file(), f"Уже существует: {path}; используйте --force.")
            outputs.append((path, height))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for path, height in outputs:
            write_output(path, patch(data, info, args.width, height), args.input, args.force)
            print(path)
        return
    if args.command == "recover":
        candidate = infer(data, info, args.width, args.max_mib * 1024 * 1024)
        width, height = candidate["width"], candidate["height"]
        if candidate.get("extra_compressed_bytes"):
            print("Примечание: после zlib-потока IDAT есть дополнительные данные; они сохранены.", file=sys.stderr)
    else:
        width, height = args.width, args.height
        require(width is not None or height is not None or info["format"] == "PNG",
                "Укажите --width или --height.")
    output = args.output or args.input.with_name(args.input.stem + ".recovered" + extension(info))
    write_output(output, patch(data, info, width, height), args.input, args.force)
    print(f"{info['format']}: {info['width']}x{info['height']} -> "
          f"{width or info['width']}x{height or info['height']}: {output}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run(args)
    except (ImageError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
