from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class SoftwareItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    product_name: str
    vendor: Optional[str] = None
    version: str
    package_name: Optional[str] = None
    install_path: Optional[str] = None
    port: Optional[int] = None
    cpe: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class SoftwareCreate(BaseModel):
    product_name: str
    vendor: Optional[str] = None
    version: str
    package_name: Optional[str] = None
    install_path: Optional[str] = None
    port: Optional[int] = None
    cpe: Optional[str] = None
