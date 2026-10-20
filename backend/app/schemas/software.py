from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class SoftwareItem(BaseModel):
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

    class Config:
        from_attributes = True


class SoftwareCreate(BaseModel):
    product_name: str
    vendor: Optional[str] = None
    version: str
    package_name: Optional[str] = None
    install_path: Optional[str] = None
    port: Optional[int] = None
    cpe: Optional[str] = None
