package com.example.foodcompanion.screens

import android.util.Log
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.absoluteOffset
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxColors
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.foodcompanion.Food
import com.example.foodcompanion.FoodManager
import com.example.foodcompanion.FoodWidget
import com.example.foodcompanion.R
import com.example.foodcompanion.data.FoodCategory
import com.example.foodcompanion.data.FoodTypes


@Composable
fun FoodsPage(
    foodType: String,
    onBackButtonClicked: (String) -> Unit = {}
) {
    var checkedStarch by remember { mutableStateOf(true) }
    var checkedVegetables by remember { mutableStateOf(true) }
    var checkedFruit by remember { mutableStateOf(true) }
    var checkedDessert by remember { mutableStateOf(true) }
    var checkedBeverages by remember { mutableStateOf(true) }
    var checkedCondiments by remember { mutableStateOf(true) }
    var checkedEntrees by remember { mutableStateOf(true) }
    Log.d("screens", foodType)
    Column {
        Spacer(modifier = Modifier.height(60.dp))
        Row() {
            IconButton(onClick = {onBackButtonClicked("test1234")}) {
                Icon(
                    painter = painterResource(id = R.drawable.arrow_back_24dp_5f6368_fill0_wght400_grad0_opsz24),
                    contentDescription = "back arrow",
                    tint = Color(0xFF222222)
                )
            }
            Spacer(modifier = Modifier.width(20.dp))
            // filters
            val checkboxColor = CheckboxColors(
                checkedCheckmarkColor = Color.White,
                uncheckedCheckmarkColor = Color.White,
                checkedBoxColor = Color(0xFF1C5D99),
                uncheckedBoxColor = Color(0xFFBBCDE5),
                disabledCheckedBoxColor = Color(0xFFBBCDE5),
                disabledUncheckedBoxColor = Color.DarkGray,
                disabledIndeterminateBorderColor = Color.Cyan,
                checkedBorderColor = Color(0xFFBBCDE5),
                disabledIndeterminateBoxColor = Color.White,
                disabledBorderColor = Color.Yellow,
                disabledUncheckedBorderColor = Color.Red,
                uncheckedBorderColor = Color(0xFF639FAB)
            )
            val filterTextColor = Color(0xFF222222)
            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxWidth()){
                Row (){
                    val modifier = Modifier
                    val colModifier = Modifier.weight(1f)
                    Column (modifier = colModifier){
                        //Starches
                        Text(
                            "Starches",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedStarch,
                            onCheckedChange = {checkedStarch = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor
                        )
                        //Vegetables
                        Text(
                            "Vegetables",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedVegetables,
                            onCheckedChange = {checkedVegetables = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                    }
                    Column(modifier = colModifier){
                        //Fruit
                        Text(
                            "Fruit",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedFruit,
                            onCheckedChange = {checkedFruit = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                        //dessert
                        Text(
                            "Dessert",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedDessert,
                            onCheckedChange = {checkedDessert = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                    }
                    Column (modifier = colModifier){

                        //Beverages
                        Text(
                            "Beverages",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedBeverages,
                            onCheckedChange = {checkedBeverages = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                        //Condiments
                        Text(
                            "Condiments",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedCondiments,
                            onCheckedChange = {checkedCondiments = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                        //Entrees
                        Text(
                            "Entrees",
                            modifier = modifier,
                            color = filterTextColor
                        )
                        Checkbox(
                            checked = checkedEntrees,
                            onCheckedChange = {checkedEntrees = it},
                            modifier = Modifier.absoluteOffset((-12).dp, 0.dp),
                            colors = checkboxColor)
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(20.dp))
        Column(modifier = Modifier.verticalScroll(rememberScrollState())){
            for (food in FoodManager.foodOptions){
                if (food.second == foodType){
                    if(
                        food.first.foodCategory == FoodTypes.Starches.name && checkedStarch ||
                        food.first.foodCategory == FoodTypes.Vegetables.name && checkedVegetables ||
                        food.first.foodCategory == FoodTypes.Fruits.name && checkedFruit ||
                        food.first.foodCategory == FoodTypes.Dessert.name && checkedDessert ||
                        food.first.foodCategory == FoodTypes.Beverages.name && checkedBeverages ||
                        food.first.foodCategory == FoodTypes.Condiments.name && checkedCondiments ||
                        food.first.foodCategory == FoodTypes.Entrees.name && checkedEntrees
                        ){
                        FoodWidget(food.first)
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                }
            }
        }
    }
}


@Preview(showBackground = true)
@Composable
fun FoodsPreview(){
FoodsPage(FoodCategory.Breakfast.name)
}