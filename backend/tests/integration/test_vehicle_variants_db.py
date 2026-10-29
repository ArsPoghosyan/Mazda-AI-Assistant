"""Vehicle-variant catalogue seed data, constraints and grants on guarded PostgreSQL."""

import pytest
from psycopg.errors import CheckViolation, InsufficientPrivilege, UniqueViolation
from sqlalchemy import delete, insert, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.models import VehicleVariant

pytestmark = pytest.mark.integration

VALID: dict[str, object] = {
    "id": 9999,
    "model_year": 2021,
    "market": "US",
    "engine": "2.5L_I4_SKYACTIV_G",
    "aspiration": "turbo",
    "transmission": "6AT",
    "drive": "FWD",
    "trim_level": "Test Trim",
    "epa_vehicle_id": None,
    "source_note": "Synthetic integration-test row",
}


def test_seed_contains_the_ten_verified_configurations(app_connection: Connection) -> None:
    rows = app_connection.execute(
        select(
            VehicleVariant.model_year,
            VehicleVariant.aspiration,
            VehicleVariant.transmission,
            VehicleVariant.epa_vehicle_id,
        ).order_by(VehicleVariant.id)
    ).all()
    assert [tuple(row) for row in rows] == [
        (2018, "naturally_aspirated", "6MT", 39845),
        (2018, "naturally_aspirated", "6AT", 39846),
        (2018, "turbo", "6AT", 39847),
        (2019, "naturally_aspirated", "6MT", 41263),
        (2019, "naturally_aspirated", "6AT", 41264),
        (2019, "turbo", "6AT", 41265),
        (2020, "naturally_aspirated", "6AT", 42304),
        (2020, "turbo", "6AT", 42305),
        (2021, "naturally_aspirated", "6AT", 43300),
        (2021, "turbo", "6AT", 43301),
    ]
    common = app_connection.execute(
        select(
            VehicleVariant.market,
            VehicleVariant.engine,
            VehicleVariant.drive,
            VehicleVariant.trim_level,
        ).distinct()
    ).all()
    assert [tuple(row) for row in common] == [("US", "2.5L_I4_SKYACTIV_G", "FWD", None)]


def test_family_car_configuration_resolves_to_one_variant(app_connection: Connection) -> None:
    variant_ids = app_connection.scalars(
        select(VehicleVariant.id).where(
            VehicleVariant.model_year == 2021,
            VehicleVariant.aspiration == "naturally_aspirated",
            VehicleVariant.transmission == "6AT",
        )
    ).all()
    assert variant_ids == [9]


@pytest.mark.parametrize(
    "statement",
    [
        insert(VehicleVariant).values(**VALID),
        update(VehicleVariant).where(VehicleVariant.id == 1).values(drive="FWD"),
        delete(VehicleVariant).where(VehicleVariant.id == 1),
    ],
    ids=["insert", "update", "delete"],
)
def test_runtime_role_cannot_change_the_catalogue(
    app_connection: Connection, statement: object
) -> None:
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(statement)  # type: ignore[call-overload]
    assert isinstance(caught.value.orig, InsufficientPrivilege)


def test_owner_can_insert_a_valid_variant(owner_connection: Connection) -> None:
    owner_connection.execute(insert(VehicleVariant).values(**VALID))
    assert (
        owner_connection.scalar(select(VehicleVariant.trim_level).where(VehicleVariant.id == 9999))
        == "Test Trim"
    )


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("model_year", 2017, "model_year_supported"),
        ("model_year", 2022, "model_year_supported"),
        ("market", "EU", "market_supported"),
        ("engine", "2.0L", "engine_supported"),
        ("aspiration", "Turbo", "aspiration_supported"),
        ("transmission", "6-spd", "transmission_supported"),
        ("drive", "AWD", "drive_supported"),
        ("drive", "RWD", "drive_supported"),
        ("trim_level", "", "trim_level_format"),
        ("trim_level", " Touring", "trim_level_format"),
        ("trim_level", "Touring<script>", "trim_level_format"),
        ("epa_vehicle_id", 0, "epa_vehicle_id_positive"),
        ("source_note", "", "source_note_format"),
        ("source_note", "line\nbreak", "source_note_format"),
    ],
)
def test_unsupported_values_are_rejected(
    owner_connection: Connection, column: str, value: object, constraint: str
) -> None:
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(insert(VehicleVariant).values(**{**VALID, column: value}))
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == f"ck_vehicle_variants_{constraint}"


@pytest.mark.parametrize(
    ("model_year", "aspiration"),
    [
        (2020, "naturally_aspirated"),
        (2021, "naturally_aspirated"),
        (2018, "turbo"),
        (2019, "turbo"),
        (2021, "turbo"),
    ],
)
def test_unlisted_manual_combinations_are_rejected(
    owner_connection: Connection, model_year: int, aspiration: str
) -> None:
    manual = {**VALID, "model_year": model_year, "aspiration": aspiration, "transmission": "6MT"}
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(insert(VehicleVariant).values(**manual))
    assert isinstance(caught.value.orig, CheckViolation)
    assert (
        caught.value.orig.diag.constraint_name
        == "ck_vehicle_variants_manual_configuration_supported"
    )


@pytest.mark.parametrize("model_year", [2018, 2019])
def test_listed_manual_combination_is_accepted(
    owner_connection: Connection, model_year: int
) -> None:
    manual = {
        **VALID,
        "model_year": model_year,
        "aspiration": "naturally_aspirated",
        "transmission": "6MT",
    }
    owner_connection.execute(insert(VehicleVariant).values(**manual))
    assert (
        owner_connection.scalar(
            select(VehicleVariant.transmission).where(VehicleVariant.id == 9999)
        )
        == "6MT"
    )


def test_duplicate_configuration_without_trim_is_rejected(owner_connection: Connection) -> None:
    # Same configuration as seeded variant 10; both have no trim.
    duplicate = {**VALID, "trim_level": None}
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(insert(VehicleVariant).values(**duplicate))
    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "uq_vehicle_variants_configuration"


def test_epa_record_cannot_back_two_variants(owner_connection: Connection) -> None:
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(
            insert(VehicleVariant).values(**{**VALID, "epa_vehicle_id": 43301})
        )
    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "uq_vehicle_variants_epa_vehicle_id"
