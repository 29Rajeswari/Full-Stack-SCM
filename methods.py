from typing import Union

from fastapi import FastAPI

from pydantic import BaseModel

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@app.post("/login")
def login(username,password):
    print(username,password)
    return {"message": "login page"}

class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}

@app.patch("/items/{item_id}")
def patch_item(item_id: int, item: dict):
    return {"message": f"Item {item_id} partially updated", "item": item}

# DELETE method - delete data
@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    return {"message": f"Item {item_id} deleted"}
